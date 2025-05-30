import uuid
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger('toolbox.task_manager')

class TaskManager:
    """Gestionnaire unifié pour toutes les tâches Celery"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self._celery_app = None
    
    @property
    def celery_app(self):
        """Lazy loading de l'app Celery"""
        if self._celery_app is None:
            from celery_app import celery_app
            self._celery_app = celery_app
        return self._celery_app
    
    # ===== LANCEMENT DE TÂCHES =====
    
    def start_discovery_task(self, target: str, user_id: int, options: Dict = None) -> Optional[str]:
        """Lance une tâche de découverte réseau"""
        try:
            # Générer un ID unique
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            db_task_id = self.db.create_task(
                task_id=task_id,
                task_name=f'Découverte → {target}',
                task_type='discovery',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import discover_network
            celery_task = discover_network.apply_async(
                args=[target, options or {}],
                task_id=task_id
            )
            
            logger.info(f"Tâche découverte lancée: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement tâche découverte: {e}")
            return None
    
    def start_test_task(self, duration: int = 10, user_id: int = None) -> Optional[str]:
        """Lance une tâche de test"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=f'Test {duration}s',
                task_type='test',
                target='localhost',
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import test_task
            celery_task = test_task.apply_async(
                args=[duration],
                task_id=task_id
            )
            
            logger.info(f"Tâche test lancée: {task_id} ({duration}s)")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement tâche test: {e}")
            return None
    
    # ===== GESTION DES TÂCHES =====
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Récupère le statut complet d'une tâche"""
        try:
            # Récupérer le statut Celery
            celery_task = self.celery_app.AsyncResult(task_id)
            
            # Récupérer les infos de la base
            tasks = self.db.get_tasks()
            db_task = next((t for t in tasks if t['task_id'] == task_id), None)
            
            if not db_task:
                return None
            
            # Combiner les informations
            status = {
                'task_id': task_id,
                'task_name': db_task['task_name'],
                'task_type': db_task['task_type'],
                'target': db_task['target'],
                'user': db_task.get('username'),
                'started_at': db_task['started_at'],
                'completed_at': db_task['completed_at'],
                
                # Statut Celery
                'celery_state': celery_task.state,
                'celery_info': celery_task.info if celery_task.info else {},
                
                # Statut base de données
                'db_status': db_task['status'],
                'progress': db_task['progress'],
                'result_summary': db_task['result_summary'],
                'error_message': db_task['error_message']
            }
            
            # Déterminer le statut unifié
            if celery_task.state == 'PENDING':
                status['unified_state'] = 'PENDING'
                status['unified_status'] = 'En attente...'
                status['unified_progress'] = 0
            elif celery_task.state == 'PROGRESS':
                status['unified_state'] = 'PROGRESS'
                status['unified_status'] = celery_task.info.get('status', 'En cours...')
                status['unified_progress'] = celery_task.info.get('progress', db_task['progress'])
            elif celery_task.state == 'SUCCESS':
                status['unified_state'] = 'SUCCESS'
                status['unified_status'] = 'Terminé avec succès'
                status['unified_progress'] = 100
                status['result'] = celery_task.result
            elif celery_task.state == 'FAILURE':
                status['unified_state'] = 'FAILURE'
                status['unified_status'] = 'Erreur'
                status['unified_progress'] = 0
                status['error'] = str(celery_task.info)
            else:
                status['unified_state'] = celery_task.state
                status['unified_status'] = db_task['status']
                status['unified_progress'] = db_task['progress']
            
            return status
            
        except Exception as e:
            logger.error(f"Erreur récupération statut tâche {task_id}: {e}")
            return None
    
    def cancel_task(self, task_id: str) -> bool:
        """Annule une tâche"""
        try:
            # Annuler dans Celery
            self.celery_app.control.revoke(task_id, terminate=True)
            
            # Mettre à jour en base
            self.db.update_task_status(
                task_id=task_id,
                status='cancelled',
                error_message='Tâche annulée par l\'utilisateur'
            )
            
            logger.info(f"Tâche annulée: {task_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur annulation tâche {task_id}: {e}")
            return False
    
    def get_task_results(self, task_id: str) -> Optional[Dict]:
        """Récupère les résultats d'une tâche terminée"""
        try:
            celery_task = self.celery_app.AsyncResult(task_id)
            
            if celery_task.state == 'SUCCESS':
                return {
                    'task_id': task_id,
                    'state': celery_task.state,
                    'result': celery_task.result,
                    'completed_at': datetime.now().isoformat()
                }
            else:
                return None
                
        except Exception as e:
            logger.error(f"Erreur récupération résultats {task_id}: {e}")
            return None
    
    # ===== CONTRÔLE D'ACCÈS =====
    
    def can_user_access_task(self, task_id: str, user_id: int, user_role: str) -> bool:
        """Vérifie si un utilisateur peut accéder à une tâche"""
        try:
            tasks = self.db.get_tasks()
            task = next((t for t in tasks if t['task_id'] == task_id), None)
            
            if not task:
                return False
            
            # Admin voit tout
            if user_role == 'admin':
                return True
            
            # L'utilisateur voit ses propres tâches
            return task.get('user_id') == user_id
            
        except Exception as e:
            logger.error(f"Erreur vérification accès tâche {task_id}: {e}")
            return False
    
    # ===== STATISTIQUES =====
    
    def get_statistics(self) -> Dict:
        """Récupère les statistiques des tâches"""
        try:
            # Statistiques Celery
            inspect = self.celery_app.control.inspect()
            active_tasks = inspect.active() or {}
            scheduled_tasks = inspect.scheduled() or {}
            reserved_tasks = inspect.reserved() or {}
            
            # Statistiques base de données
            stats = self.db.get_stats()
            
            return {
                'celery': {
                    'active': sum(len(tasks) for tasks in active_tasks.values()),
                    'scheduled': sum(len(tasks) for tasks in scheduled_tasks.values()),
                    'reserved': sum(len(tasks) for tasks in reserved_tasks.values()),
                    'workers': len(inspect.stats() or {})
                },
                'database': stats.get('tasks', {}),
                'combined': {
                    'total_active': sum(len(tasks) for tasks in active_tasks.values()),
                    'total_completed': stats.get('tasks', {}).get('completed', 0),
                    'total_failed': stats.get('tasks', {}).get('failed', 0)
                }
            }
            
        except Exception as e:
            logger.error(f"Erreur statistiques tâches: {e}")
            return {
                'celery': {'active': 0, 'scheduled': 0, 'reserved': 0, 'workers': 0},
                'database': {},
                'combined': {'total_active': 0, 'total_completed': 0, 'total_failed': 0}
            }
    
    # ===== MAINTENANCE =====
    
    def cleanup_orphaned_tasks(self) -> int:
        """Nettoie les tâches orphelines (présentes en base mais plus dans Celery)"""
        try:
            # Récupérer les tâches actives en base
            active_tasks_db = self.db.get_tasks()
            active_tasks_db = [t for t in active_tasks_db if t['status'] not in ['completed', 'failed', 'cancelled']]
            
            cleaned_count = 0
            
            for task in active_tasks_db:
                task_id = task['task_id']
                celery_task = self.celery_app.AsyncResult(task_id)
                
                # Si la tâche n'existe plus dans Celery, la marquer comme échouée
                if celery_task.state == 'PENDING' and not self._task_exists_in_celery(task_id):
                    self.db.update_task_status(
                        task_id=task_id,
                        status='failed',
                        error_message='Tâche orpheline - worker indisponible'
                    )
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Nettoyage: {cleaned_count} tâches orphelines trouvées")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Erreur nettoyage tâches orphelines: {e}")
            return 0
    
    def _task_exists_in_celery(self, task_id: str) -> bool:
        """Vérifie si une tâche existe réellement dans Celery"""
        try:
            inspect = self.celery_app.control.inspect()
            
            # Vérifier dans les tâches actives
            active = inspect.active() or {}
            for worker_tasks in active.values():
                if any(task.get('id') == task_id for task in worker_tasks):
                    return True
            
            # Vérifier dans les tâches programmées
            scheduled = inspect.scheduled() or {}
            for worker_tasks in scheduled.values():
                if any(task.get('id') == task_id for task in worker_tasks):
                    return True
            
            # Vérifier dans les tâches réservées
            reserved = inspect.reserved() or {}
            for worker_tasks in reserved.values():
                if any(task.get('id') == task_id for task in worker_tasks):
                    return True
            
            return False
            
        except Exception:
            return False

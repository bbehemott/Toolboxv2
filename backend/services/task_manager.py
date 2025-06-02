import uuid
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger('toolbox.task_manager')

class TaskManager:
    """Gestionnaire unifié pour toutes les tâches Celery - Version vierge"""
    
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
    
    def start_example_task(self, target: str, user_id: int = None, options: Dict = None) -> Optional[str]:
        """Lance une tâche exemple - Template pour futurs modules"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=f'Exemple → {target}',
                task_type='example',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import example_task
            celery_task = example_task.apply_async(
                args=[target, options or {}],
                task_id=task_id
            )
            
            logger.info(f"Tâche exemple lancée: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement tâche exemple: {e}")
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
    

    def start_huntkit_discovery(self, target: str, user_id: int = None, options: Dict = None) -> Optional[str]:
        """Lance une tâche de découverte réseau HuntKit"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=f'🌐 Découverte → {target}',
                task_type='huntkit_discovery',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks_huntkit import huntkit_network_discovery
            celery_task = huntkit_network_discovery.apply_async(
                args=[target, options or {}],
                task_id=task_id
            )
            
            logger.info(f"Tâche découverte HuntKit lancée: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement découverte HuntKit: {e}")
            return None

    def start_huntkit_web_audit(self, target: str, port: int = 80, ssl: bool = False, 
                               user_id: int = None, options: Dict = None) -> Optional[str]:
        """Lance une tâche d'audit web HuntKit"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=f'🕷️ Audit Web → {target}:{port}',
                task_type='huntkit_web_audit',
                target=f'{target}:{port}',
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks_huntkit import huntkit_web_audit
            celery_task = huntkit_web_audit.apply_async(
                args=[target, port, ssl, options or {}],
                task_id=task_id
            )
            
            logger.info(f"Tâche audit web HuntKit lancée: {task_id} pour {target}:{port}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement audit web HuntKit: {e}")
            return None

    def start_huntkit_brute_force(self, target: str, service: str, username: str = None,
                                 userlist: str = None, passwordlist: str = None,
                                 user_id: int = None, options: Dict = None) -> Optional[str]:
        """Lance une tâche de force brute HuntKit"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=f'🔨 Force Brute → {target} ({service})',
                task_type='huntkit_brute_force',
                target=f'{target}:{service}',
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks_huntkit import huntkit_brute_force
            celery_task = huntkit_brute_force.apply_async(
                args=[target, service, username, userlist, passwordlist, options or {}],
                task_id=task_id
            )
            
            logger.info(f"Tâche force brute HuntKit lancée: {task_id} pour {target}:{service}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement force brute HuntKit: {e}")
            return None

    def start_huntkit_full_pentest(self, target: str, user_id: int = None, options: Dict = None) -> Optional[str]:
        """Lance un pentest complet HuntKit"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=f'🎯 Pentest Complet → {target}',
                task_type='huntkit_full_pentest',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks_huntkit import huntkit_full_pentest
            celery_task = huntkit_full_pentest.apply_async(
                args=[target, options or {}],
                task_id=task_id
            )
            
            logger.info(f"Tâche pentest complet HuntKit lancée: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement pentest complet HuntKit: {e}")
            return None

    def start_tools_verification(self, user_id: int = None) -> Optional[str]:
        """Lance une vérification des outils HuntKit"""
        try:
            task_id = str(uuid.uuid4())
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name='🔧 Vérification Outils HuntKit',
                task_type='huntkit_tools_check',
                target='localhost',
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks_huntkit import huntkit_tools_verification
            celery_task = huntkit_tools_verification.apply_async(
                task_id=task_id
            )
            
            logger.info(f"Tâche vérification outils HuntKit lancée: {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Erreur lancement vérification outils HuntKit: {e}")
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



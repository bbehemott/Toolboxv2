import uuid
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger('toolbox.task_manager')

class TaskManager:
    """Gestionnaire unifié pour toutes les tâches Celery - Version sans Masscan"""
    
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
    
    # ===== LANCEMENT DE TÂCHES EXISTANTES =====
    
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
    
    # ===== TÂCHES PENTEST PRINCIPALES =====
    
    def start_discovery_task(self, target: str, options: Dict = None, user_id: int = None) -> Optional[str]:
        """Lance une tâche de découverte réseau (Nmap uniquement)"""
        try:
            task_id = str(uuid.uuid4())
            
            # Déterminer le nom de la tâche
            task_name = f'Découverte Nmap → {target}'
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=task_name,
                task_type='network_discovery',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import network_discovery
            celery_task = network_discovery.apply_async(
                args=[target, options or {}],
                task_id=task_id
            )
            
            logger.info(f"🌐 Tâche découverte lancée: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"❌ Erreur lancement découverte: {e}")
            return None

    def start_port_scan_task(self, target: str, options: Dict = None, user_id: int = None) -> Optional[str]:
        """Lance une tâche de scan de ports"""
        try:
            task_id = str(uuid.uuid4())
            
            # Déterminer les options d'affichage
            ports = options.get('ports', 'top_1000') if options else 'top_1000'
            task_name = f'Scan Ports ({ports}) → {target}'
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=task_name,
                task_type='port_scan',
                target=target,
                user_id=user_id
            )
            
            # Pour le scan de ports direct, créer une structure de données d'hôtes
            hosts_data = {
                'hosts': [{'ip': target}],
                'target': target
            }
            
            # Lancer la tâche Celery
            from tasks import port_scan
            celery_task = port_scan.apply_async(
                args=[hosts_data, options or {}],
                task_id=task_id
            )
            
            logger.info(f"🔍 Tâche scan ports lancée: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"❌ Erreur lancement scan ports: {e}")
            return None

    def start_full_audit_task(self, target: str, config: Dict = None, user_id: int = None) -> Optional[str]:
        """Lance un audit complet automatisé"""
        try:
            task_id = str(uuid.uuid4())
            
            task_name = f'Audit Complet → {target}'
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=task_name,
                task_type='full_audit',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery d'orchestration
            from tasks import full_network_audit
            celery_task = full_network_audit.apply_async(
                args=[target, config or {}],
                task_id=task_id
            )
            
            logger.info(f"🎯 Audit complet lancé: {task_id} pour {target}")
            return task_id
            
        except Exception as e:
            logger.error(f"❌ Erreur lancement audit complet: {e}")
            return None

    def start_vulnerability_scan_task(self, hosts_data: Dict, options: Dict = None, user_id: int = None) -> Optional[str]:
        """Lance une tâche de scan de vulnérabilités"""
        try:
            task_id = str(uuid.uuid4())
            
            # Compter les hôtes à scanner
            hosts_count = len(hosts_data.get('hosts', []))
            target = hosts_data.get('target', 'Multiple hosts')
            task_name = f'Scan Vulnérabilités → {hosts_count} hôte(s)'
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=task_name,
                task_type='vulnerability_scan',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import vulnerability_scan
            celery_task = vulnerability_scan.apply_async(
                args=[hosts_data, options or {}],
                task_id=task_id
            )
            
            logger.info(f"🚨 Scan vulnérabilités lancé: {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"❌ Erreur lancement scan vulnérabilités: {e}")
            return None

    def start_service_enumeration_task(self, hosts_data: Dict, options: Dict = None, user_id: int = None) -> Optional[str]:
        """Lance une tâche d'énumération de services"""
        try:
            task_id = str(uuid.uuid4())
            
            hosts_count = len(hosts_data.get('hosts', []))
            target = hosts_data.get('target', 'Multiple hosts')
            task_name = f'Énumération Services → {hosts_count} hôte(s)'
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=task_name,
                task_type='service_enumeration',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import service_enumeration
            celery_task = service_enumeration.apply_async(
                args=[hosts_data, options or {}],
                task_id=task_id
            )
            
            logger.info(f"🔧 Énumération services lancée: {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"❌ Erreur lancement énumération services: {e}")
            return None

    def start_exploitation_task(self, vulnerabilities_data: Dict, options: Dict = None, user_id: int = None) -> Optional[str]:
        """Lance une tâche d'exploitation"""
        try:
            task_id = str(uuid.uuid4())
            
            vulns_count = len(vulnerabilities_data.get('vulnerabilities', []))
            target = vulnerabilities_data.get('target', 'Multiple targets')
            task_name = f'Exploitation → {vulns_count} vulnérabilité(s)'
            
            # Enregistrer en base
            self.db.create_task(
                task_id=task_id,
                task_name=task_name,
                task_type='exploitation',
                target=target,
                user_id=user_id
            )
            
            # Lancer la tâche Celery
            from tasks import exploitation
            celery_task = exploitation.apply_async(
                args=[vulnerabilities_data, options or {}],
                task_id=task_id
            )
            
            logger.info(f"💥 Exploitation lancée: {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"❌ Erreur lancement exploitation: {e}")
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
    
    # ===== MONITORING ET PROGRESSION =====
    
    def get_audit_progress(self, task_id: str) -> Dict:
        """Récupère la progression détaillée d'un audit complet"""
        try:
            # Récupérer le statut de la tâche principale
            main_status = self.get_task_status(task_id)
            
            if not main_status:
                return {
                    'success': False,
                    'error': 'Tâche non trouvée'
                }
            
            # Récupérer tous les résultats de modules liés
            module_results = self.db.get_module_results(task_id)
            
            # Analyser la progression par phase
            phases = {
                'discovery': {'completed': False, 'success': False, 'data': None},
                'port_scan': {'completed': False, 'success': False, 'data': None},
                'service_enum': {'completed': False, 'success': False, 'data': None},
                'vulnerability_scan': {'completed': False, 'success': False, 'data': None},
                'exploitation': {'completed': False, 'success': False, 'data': None}
            }
            
            for result in module_results:
                module_name = result['module_name']
                result_data = result['result_data']
                
                if module_name in phases:
                    phases[module_name]['completed'] = True
                    phases[module_name]['success'] = result_data.get('success', False)
                    phases[module_name]['data'] = result_data
            
            # Calculer la progression globale
            completed_phases = sum(1 for phase in phases.values() if phase['completed'])
            total_phases = len(phases)
            overall_progress = (completed_phases / total_phases) * 100
            
            return {
                'success': True,
                'task_id': task_id,
                'overall_progress': overall_progress,
                'phases': phases,
                'completed_phases': completed_phases,
                'total_phases': total_phases,
                'main_status': main_status
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur progression audit {task_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_pentest_summary(self, user_id: int = None, days: int = 30) -> Dict:
        """Récupère un résumé des activités de pentest"""
        try:
            # Récupérer les tâches récentes
            if user_id:
                recent_tasks = self.db.get_tasks(user_id=user_id, limit=50)
            else:
                recent_tasks = self.db.get_tasks(limit=50)
            
            # Filtrer les tâches de pentest
            pentest_tasks = [
                task for task in recent_tasks
                if task.get('task_type') in ['network_discovery', 'port_scan', 'vulnerability_scan', 'full_audit']
            ]
            
            # Analyser les résultats
            summary = {
                'total_scans': len(pentest_tasks),
                'successful_scans': len([t for t in pentest_tasks if t.get('status') == 'completed']),
                'failed_scans': len([t for t in pentest_tasks if t.get('status') == 'failed']),
                'running_scans': len([t for t in pentest_tasks if t.get('status') == 'running']),
                'scan_types': {},
                'recent_targets': []
            }
            
            # Compter par type de scan
            for task in pentest_tasks:
                task_type = task.get('task_type', 'unknown')
                summary['scan_types'][task_type] = summary['scan_types'].get(task_type, 0) + 1
            
            # Top des cibles récentes
            targets = {}
            for task in pentest_tasks[:20]:  # 20 plus récentes
                target = task.get('target')
                if target:
                    targets[target] = targets.get(target, 0) + 1
            
            summary['recent_targets'] = sorted(targets.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'success': True,
                'summary': summary,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur résumé pentest: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
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

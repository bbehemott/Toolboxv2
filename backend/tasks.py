from celery_app import celery_app
from celery import current_task
import logging
import time
from typing import Dict, Any

logger = logging.getLogger(__name__)

# ===== ACCÈS À LA BASE DE DONNÉES =====
def get_db_manager():
    """Accès simplifié au gestionnaire de base de données"""
    try:
        from database import DatabaseManager
        from config import config
        
        config_obj = config.get('development', config['default'])
        return DatabaseManager(config_obj.DATABASE_PATH)
    except Exception as e:
        logger.error(f"❌ Erreur accès BDD dans Celery: {e}")
        return None

# ===== TÂCHE TEST =====
@celery_app.task(bind=True, name='tasks.test_task')
def test_task(self, duration: int = 10):
    """Tâche de test pour vérifier Celery"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🧪 [Celery] Test task démarré: {duration}s")
        
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        for i in range(duration):
            time.sleep(1)
            progress = int((i + 1) / duration * 100)
            
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Test en cours... {i+1}/{duration}',
                    'progress': progress
                }
            )
            
            db.update_task_status(
                task_id=self.request.id,
                status='running',
                progress=progress
            )
        
        result = {
            'task_id': self.request.id,
            'duration': duration,
            'success': True,
            'message': f'Test task terminé après {duration} secondes',
            'completed_at': time.time()
        }
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=f'Test de {duration}s terminé avec succès'
        )
        
        logger.info(f"✅ [Celery] Test task terminé")
        return result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception test task: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

# ===== TEMPLATE POUR FUTURES TÂCHES =====
@celery_app.task(bind=True, name='tasks.example_task')
def example_task(self, target: str, options: Dict = None):
    """Template pour futures tâches de modules"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🔧 [Celery] Exemple de tâche pour: {target}")
        
        # Mise à jour du statut
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Initialisation...', 'progress': 10, 'target': target}
        )
        
        # Simulation de travail
        for i in range(5):
            time.sleep(1)
            progress = 20 + (i * 16)
            
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Étape {i+1}/5',
                    'progress': progress,
                    'target': target
                }
            )
            
            db.update_task_status(
                task_id=self.request.id,
                status='running',
                progress=progress
            )
        
        # Résultat final
        result = {
            'task_id': self.request.id,
            'target': target,
            'success': True,
            'message': 'Tâche exemple terminée',
            'completed_at': time.time(),
            'data': {
                'example_field': 'example_value',
                'target': target,
                'options': options or {}
            }
        }
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=f'Tâche exemple terminée pour {target}'
        )
        
        logger.info(f"✅ [Celery] Tâche exemple terminée")
        return result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception tâche exemple: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

# ===== UTILITAIRE =====
def get_task_status(task_id: str) -> Dict[str, Any]:
    """Récupérer le statut d'une tâche Celery"""
    try:
        task = celery_app.AsyncResult(task_id)
        
        if task.state == 'PENDING':
            return {'state': 'PENDING', 'status': 'En attente...', 'progress': 0}
        elif task.state == 'PROGRESS':
            return {
                'state': 'PROGRESS',
                'status': task.info.get('status', 'En cours...'),
                'progress': task.info.get('progress', 0),
                'meta': task.info
            }
        elif task.state == 'SUCCESS':
            return {
                'state': 'SUCCESS',
                'status': 'Terminé avec succès',
                'progress': 100,
                'result': task.result
            }
        elif task.state == 'FAILURE':
            return {
                'state': 'FAILURE',
                'status': 'Erreur',
                'progress': 0,
                'error': str(task.info)
            }
        else:
            return {'state': task.state, 'status': 'Statut inconnu', 'progress': 0}
            
    except Exception as e:
        logger.error(f"Erreur récupération statut tâche {task_id}: {e}")
        return {'state': 'ERROR', 'status': f'Erreur: {str(e)}', 'progress': 0}

import os
from celery import Celery
import logging

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def make_celery():
    """Créer et configurer l'instance Celery - VERSION SÉCURISÉE"""
    
    # URLs Redis depuis les variables d'environnement
    broker_url = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
    result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    
    # ✅ CORRECTION : Import sécurisé des modules
    available_modules = ['tasks']  # Module de base toujours présent
    
    # Tenter d'importer le module HuntKit
    try:
        import tasks_huntkit
        available_modules.append('tasks_huntkit')
        logger.info("✅ Module HuntKit détecté et ajouté")
    except ImportError as e:
        logger.warning(f"⚠️ Module HuntKit non disponible: {e}")
        logger.info("📋 Démarrage en mode de base (sans HuntKit)")
    
    # Créer l'instance Celery avec les modules disponibles
    celery = Celery(
        'toolbox',
        broker=broker_url,
        backend=result_backend,
        include=available_modules  # ✅ Seulement les modules qui existent
    )
    
    # Configuration Celery
    celery.conf.update(
        # ===== CONFIGURATION GÉNÉRALE =====
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='Europe/Paris',
        enable_utc=True,
        
        # ===== PERFORMANCE ET TIMEOUTS =====
        task_soft_time_limit=3600,      # 1 heure limite souple
        task_time_limit=7200,           # 2 heures limite dure
        worker_prefetch_multiplier=1,   # Une tâche à la fois par worker
        task_acks_late=True,           # Confirmer seulement si succès
        worker_disable_rate_limits=False,
        
        # ===== RETRY ET ERROR HANDLING =====
        task_reject_on_worker_lost=True,
        task_default_retry_delay=60,    # 1 minute entre retries
        task_max_retries=3,
        
        # ===== MONITORING =====
        worker_send_task_events=True,
        task_send_sent_event=True,
        
        # ===== OPTIMISATIONS POUR SCANS LONGS =====
        result_expires=86400,          # Résultats gardés 24h
        task_ignore_result=False,      # Garder les résultats
        
        # ===== CELERY 6.0+ COMPATIBILITY =====
        broker_connection_retry_on_startup=True,  # ✅ Fix warning Celery 6.0+
        
        # ===== ROUTES DES TÂCHES DYNAMIQUES =====
        task_routes={
            # Tâches de base
            'tasks.test_task': {'queue': 'default'},
        },
        
        # ===== CONFIGURATION DES QUEUES =====
        task_default_queue='default',
        task_queues={
            'default': {
                'exchange': 'default',
                'routing_key': 'default',
            },
            'discovery': {
                'exchange': 'discovery',
                'routing_key': 'discovery',
            }
        }
    )
    
    # ✅ Ajouter routes HuntKit si disponible
    if 'tasks_huntkit' in available_modules:
        huntkit_routes = {
            'tasks.huntkit_discovery': {'queue': 'discovery'},
            'tasks.huntkit_web_audit': {'queue': 'discovery'},
            'tasks.huntkit_brute_force': {'queue': 'discovery'},
            'tasks.huntkit_full_pentest': {'queue': 'discovery'},
            'tasks.huntkit_tools_check': {'queue': 'default'},
        }
        celery.conf.task_routes.update(huntkit_routes)
        logger.info("🎯 Routes HuntKit configurées")
    
    logger.info(f"✅ Celery configuré - Broker: {broker_url}")
    logger.info(f"📋 Modules chargés: {', '.join(available_modules)}")
    return celery

# Créer l'instance globale
celery_app = make_celery()

# ===== AUTO-DÉCOUVERTE DES TÂCHES SÉCURISÉE =====
try:
    # Importer explicitement le module de base
    import tasks
    logger.info("✅ Module tasks importé")
    
    # Tenter d'importer HuntKit
    try:
        import tasks_huntkit
        logger.info("✅ Module tasks_huntkit importé")
    except ImportError:
        logger.info("📋 Module tasks_huntkit non disponible - mode dégradé")
        
except ImportError as e:
    logger.error(f"❌ Erreur critique import modules: {e}")

if __name__ == '__main__':
    celery_app.start()

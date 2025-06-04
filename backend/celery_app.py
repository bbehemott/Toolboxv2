import os
from celery import Celery
import logging

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def make_celery():
    """Créer et configurer l'instance Celery - VERSION AVEC METASPLOIT"""
    
    # URLs Redis depuis les variables d'environnement
    broker_url = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
    result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    
    # ✅ CORRECTION : Import sécurisé des modules avec Metasploit
    available_modules = ['tasks']  # Module de base toujours présent
    
    # Tenter d'importer le module HuntKit
    try:
        import tasks_huntkit
        available_modules.append('tasks_huntkit')
        logger.info("✅ Module HuntKit détecté et ajouté")
        
        # Vérifier la présence des tâches Metasploit
        metasploit_tasks = [
            'metasploit_exploitation',
            'metasploit_search_exploits', 
            'metasploit_test_framework'
        ]
        
        found_metasploit_tasks = []
        for task_name in metasploit_tasks:
            if hasattr(tasks_huntkit, task_name):
                found_metasploit_tasks.append(task_name)
        
        logger.info(f"🎯 Tâches Metasploit trouvées: {len(found_metasploit_tasks)}/{len(metasploit_tasks)}")
        
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
        
        # ===== PERFORMANCE ET TIMEOUTS ADAPTÉS METASPLOIT =====
        task_soft_time_limit=1800,      # 30 minutes limite souple (pour Metasploit)
        task_time_limit=3600,           # 1 heure limite dure (exploitations longues)
        worker_prefetch_multiplier=1,   # Une tâche à la fois par worker
        task_acks_late=True,           # Confirmer seulement si succès
        worker_disable_rate_limits=False,
        
        # ===== RETRY ET ERROR HANDLING =====
        task_reject_on_worker_lost=True,
        task_default_retry_delay=60,    # 1 minute entre retries
        task_max_retries=2,             # Moins de retries pour Metasploit
        
        # ===== MONITORING =====
        worker_send_task_events=True,
        task_send_sent_event=True,
        
        # ===== OPTIMISATIONS POUR METASPLOIT =====
        result_expires=172800,         # Résultats gardés 48h (2 jours)
        task_ignore_result=False,      # Garder les résultats
        
        # ===== CELERY 6.0+ COMPATIBILITY =====
        broker_connection_retry_on_startup=True,  # ✅ Fix warning Celery 6.0+
        
        # ===== ROUTES DES TÂCHES AVEC METASPLOIT =====
        task_routes={
            # Tâches de base
            'tasks.test_task': {'queue': 'default'},
            
            # ===== NOUVELLES ROUTES METASPLOIT =====
            'tasks.exploitation': {'queue': 'exploitation'},
            'tasks.metasploit_search': {'queue': 'default'},
            'tasks.metasploit_test': {'queue': 'default'},
        },
        
        # ===== CONFIGURATION DES QUEUES AVEC METASPLOIT =====
        task_default_queue='default',
        task_queues={
            'default': {
                'exchange': 'default',
                'routing_key': 'default',
            },
            'discovery': {
                'exchange': 'discovery',
                'routing_key': 'discovery',
            },
            'exploitation': {  # ✅ NOUVELLE QUEUE POUR METASPLOIT
                'exchange': 'exploitation',
                'routing_key': 'exploitation',
            }
        }
    )
    
    # ✅ Ajouter routes HuntKit si disponible
    if 'tasks_huntkit' in available_modules:
        huntkit_routes = {
            # Routes existantes
            'tasks.huntkit_discovery': {'queue': 'discovery'},
            'tasks.huntkit_web_audit': {'queue': 'discovery'},
            'tasks.huntkit_brute_force': {'queue': 'discovery'},
            'tasks.huntkit_full_pentest': {'queue': 'discovery'},
            'tasks.huntkit_tools_check': {'queue': 'default'},
            
            # ✅ NOUVELLES ROUTES METASPLOIT
            'tasks_huntkit.metasploit_exploitation': {'queue': 'exploitation'},
            'tasks_huntkit.metasploit_search_exploits': {'queue': 'default'},
            'tasks_huntkit.metasploit_test_framework': {'queue': 'default'},
        }
        celery.conf.task_routes.update(huntkit_routes)
        logger.info("🎯 Routes HuntKit + Metasploit configurées")
    
    logger.info(f"✅ Celery configuré - Broker: {broker_url}")
    logger.info(f"📋 Modules chargés: {', '.join(available_modules)}")
    logger.info(f"🎯 Queues configurées: default, discovery, exploitation")
    return celery

# Créer l'instance globale
celery_app = make_celery()

# ===== AUTO-DÉCOUVERTE DES TÂCHES SÉCURISÉE AVEC METASPLOIT =====
try:
    # Importer explicitement le module de base
    import tasks
    logger.info("✅ Module tasks importé")
    
    # Tenter d'importer HuntKit avec Metasploit
    try:
        import tasks_huntkit
        logger.info("✅ Module tasks_huntkit importé")
        
        # Vérification spéciale pour les tâches Metasploit
        metasploit_tasks = [
            'metasploit_exploitation',
            'metasploit_search_exploits',
            'metasploit_test_framework'
        ]
        
        available_metasploit_tasks = []
        for task_name in metasploit_tasks:
            if hasattr(tasks_huntkit, task_name):
                available_metasploit_tasks.append(task_name)
                logger.info(f"✅ Tâche Metasploit trouvée: {task_name}")
            else:
                logger.warning(f"⚠️ Tâche Metasploit manquante: {task_name}")
        
        if len(available_metasploit_tasks) == len(metasploit_tasks):
            logger.info("🎯 TOUTES les tâches Metasploit sont disponibles !")
        else:
            logger.warning(f"⚠️ Seulement {len(available_metasploit_tasks)}/{len(metasploit_tasks)} tâches Metasploit disponibles")
            
    except ImportError:
        logger.info("📋 Module tasks_huntkit non disponible - mode dégradé")
        
except ImportError as e:
    logger.error(f"❌ Erreur critique import modules: {e}")

# ===== HOOKS POUR MONITORING METASPLOIT =====
@celery_app.task(bind=True)
def debug_task(self):
    """Tâche de debug pour tester Celery + Metasploit"""
    print(f'Request: {self.request!r}')
    
    # Test d'import Metasploit
    try:
        from core.huntkit_tools import HuntKitIntegration
        huntkit = HuntKitIntegration()
        msf_status = huntkit.metasploit.test_metasploit_availability()
        
        return {
            'celery_ok': True,
            'metasploit_available': msf_status.get('available', False),
            'metasploit_version': msf_status.get('version', 'Unknown'),
            'timestamp': str(datetime.now())
        }
    except Exception as e:
        return {
            'celery_ok': True,
            'metasploit_available': False,
            'error': str(e),
            'timestamp': str(datetime.now())
        }

if __name__ == '__main__':
    # Test rapide avant démarrage
    logger.info("🧪 Test rapide de l'intégration Metasploit...")
    
    try:
        from core.huntkit_tools import HuntKitIntegration
        huntkit = HuntKitIntegration()
        msf_test = huntkit.metasploit.test_metasploit_availability()
        
        if msf_test.get('available'):
            logger.info(f"✅ Metasploit opérationnel: {msf_test.get('version', 'Version inconnue')}")
        else:
            logger.warning(f"⚠️ Metasploit non disponible: {msf_test.get('error', 'Erreur inconnue')}")
            
    except Exception as e:
        logger.error(f"❌ Erreur test Metasploit au démarrage: {e}")
    
    celery_app.start()

# backend/celery_app.py - Configuration Celery
import os
from celery import Celery
import logging

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def make_celery():
    """Créer et configurer l'instance Celery"""
    
    # URLs Redis depuis les variables d'environnement
    broker_url = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
    result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    
    # Créer l'instance Celery
    celery = Celery(
        'toolbox',
        broker=broker_url,
        backend=result_backend,
        include=['tasks']  # Module contenant les tâches
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
        
        # ===== ROUTES DES TÂCHES =====
        task_routes={
            'tasks.discover_network': {'queue': 'discovery'},
            'tasks.scan_vulnerabilities': {'queue': 'vulnscans'},
            'tasks.exploit_target': {'queue': 'exploitation'},
            'tasks.nmap_scan': {'queue': 'portscans'},
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
            },
            'vulnscans': {
                'exchange': 'vulnscans', 
                'routing_key': 'vulnscans',
            },
            'portscans': {
                'exchange': 'portscans',
                'routing_key': 'portscans', 
            },
            'exploitation': {
                'exchange': 'exploitation',
                'routing_key': 'exploitation',
            }
        }
    )
    
    logger.info(f"✅ Celery configuré - Broker: {broker_url}")
    return celery

# Créer l'instance globale
celery_app = make_celery()

if __name__ == '__main__':
    celery_app.start()

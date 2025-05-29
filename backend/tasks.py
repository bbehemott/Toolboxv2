from celery_app import celery_app
from celery import current_task
from celery.exceptions import Retry
import logging
import time
import json
from typing import Dict, Any

# ✅ CORRECTION : Imports pour nouvelle architecture
from modules.decouverte_reseau import DecouverteReseauModule
from core.nmap_wrapper import NmapWrapper
from database import DatabaseManager
from config import config

logger = logging.getLogger(__name__)

# ✅ NOUVELLE FONCTION : Accès à la base unifiée
def get_db_manager():
    """Accès au gestionnaire de base de données unifié"""
    try:
        config_obj = config.get('development', config['default'])
        return DatabaseManager(config_obj.DATABASE_PATH)
    except Exception as e:
        logger.error(f"Erreur accès BDD: {e}")
        return None

# ===== TÂCHE DÉCOUVERTE RÉSEAU CORRIGÉE =====
@celery_app.task(bind=True, name='tasks.discover_network')
def discover_network(self, target: str, options: Dict = None):
    """Tâche asynchrone pour la découverte réseau"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🌐 [Celery] Début découverte réseau: {target}")
        
        # ✅ CORRECTION : Mise à jour du statut via le nouveau système
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        # Mise à jour du statut Celery
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Initialisation...', 'progress': 10, 'target': target}
        )
        
        # Initialiser le module découverte
        decouverte_module = DecouverteReseauModule()
        
        # Callback pour progression
        def progress_callback(phase: str, progress: int):
            # Mettre à jour Celery
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Phase: {phase}',
                    'progress': progress,
                    'target': target,
                    'phase': phase
                }
            )
            # Mettre à jour la BDD
            db.update_task_status(
                task_id=self.request.id,
                status='running',
                progress=progress
            )
        
        # Exécuter la découverte complète
        progress_callback('Découverte réseau', 30)
        result = decouverte_module.execute_full_discovery(target, options)
        
        # Préparer le résultat final
        final_result = {
            'task_id': self.request.id,
            'target': target,
            'success': result.get('success', False),
            'completed_at': time.time(),
            'result_data': result
        }
        
        # ✅ CORRECTION : Mettre à jour le statut final dans la BDD unifiée
        if result.get('success'):
            logger.info(f"✅ [Celery] Découverte terminée: {target}")
            progress_callback('Terminé avec succès', 100)
            
            # Sauvegarder le succès
            hosts_found = len(result.get('hosts', []))
            summary = f"Trouvé {hosts_found} hôte(s) actif(s)"
            
            db.update_task_status(
                task_id=self.request.id,
                status='completed',
                progress=100,
                result_summary=summary
            )
        else:
            logger.error(f"❌ [Celery] Erreur découverte: {result.get('error')}")
            db.update_task_status(
                task_id=self.request.id,
                status='failed',
                error_message=result.get('error', 'Erreur inconnue')
            )
            
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception découverte {target}: {e}")
        
        # Sauvegarder l'erreur
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        
        self.update_state(
            state='FAILURE',
            meta={
                'status': f'Erreur: {str(e)}',
                'target': target,
                'error': str(e)
            }
        )
        raise

# ===== TÂCHE NMAP CORRIGÉE =====
@celery_app.task(bind=True, name='tasks.nmap_scan')
def nmap_scan(self, target: str, scan_type: str = 'quick', ports: str = None):
    """Tâche asynchrone pour scan Nmap"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🔍 [Celery] Début scan Nmap: {target} ({scan_type})")
        
        # Mise à jour initiale
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Initialisation Nmap...', 'progress': 10, 'target': target}
        )
        
        # Initialiser Nmap
        nmap = NmapWrapper()
        
        # Mise à jour progression
        self.update_state(
            state='PROGRESS',
            meta={'status': f'Scan {scan_type} en cours...', 'progress': 30, 'target': target}
        )
        
        # Exécuter selon le type
        if scan_type == 'quick':
            result = nmap.quick_scan(target)
        elif scan_type == 'port':
            result = nmap.port_scan(target, ports or "1-1000")
        elif scan_type == 'service':
            result = nmap.service_enumeration(target, ports)
        elif scan_type == 'vulnerability':
            result = nmap.vulnerability_scan(target)
        else:
            result = nmap.quick_scan(target)
        
        # Finalisation
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Traitement des résultats...', 'progress': 90, 'target': target}
        )
        
        final_result = {
            'task_id': self.request.id,
            'target': target,
            'scan_type': scan_type,
            'success': result.get('success', False),
            'completed_at': time.time(),
            'result_data': result
        }
        
        # Mettre à jour le statut final
        if result.get('success'):
            logger.info(f"✅ [Celery] Scan Nmap terminé: {target}")
            
            # Créer résumé selon le type
            if scan_type == 'port':
                ports_found = len(result.get('open_ports', []))
                summary = f"Trouvé {ports_found} port(s) ouvert(s)"
            elif scan_type == 'service':
                services_found = len(result.get('services', []))
                summary = f"Identifié {services_found} service(s)"
            elif scan_type == 'vulnerability':
                vulns_found = len(result.get('vulnerabilities', []))
                summary = f"Trouvé {vulns_found} vulnérabilité(s)"
            else:
                ports_found = len(result.get('open_ports', []))
                summary = f"Scan rapide: {ports_found} port(s)"
            
            db.update_task_status(
                task_id=self.request.id,
                status='completed',
                progress=100,
                result_summary=summary
            )
        else:
            logger.error(f"❌ [Celery] Erreur Nmap: {result.get('error')}")
            db.update_task_status(
                task_id=self.request.id,
                status='failed',
                error_message=result.get('error', 'Erreur scan Nmap')
            )
            
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception scan Nmap {target}: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        
        self.update_state(
            state='FAILURE',
            meta={
                'status': f'Erreur: {str(e)}',
                'target': target,
                'error': str(e)
            }
        )
        raise

# ===== TÂCHE SCAN VULNÉRABILITÉS =====
@celery_app.task(bind=True, name='tasks.vulnerability_scan')
def vulnerability_scan(self, target: str, scripts: str = 'vuln'):
    """Tâche asynchrone pour scan de vulnérabilités avec Nmap NSE"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"⚠️ [Celery] Début scan vulnérabilités: {target}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Initialisation scan vulnérabilités...', 'progress': 10, 'target': target}
        )
        
        # Utiliser le wrapper Nmap pour les vulnérabilités
        nmap = NmapWrapper()
        
        self.update_state(
            state='PROGRESS',
            meta={'status': f'Scripts NSE {scripts}...', 'progress': 40, 'target': target}
        )
        
        result = nmap.vulnerability_scan(target, scripts)
        
        final_result = {
            'task_id': self.request.id,
            'target': target,
            'scripts': scripts,
            'success': result.get('success', False),
            'completed_at': time.time(),
            'result_data': result
        }
        
        if result.get('success'):
            logger.info(f"✅ [Celery] Scan vulnérabilités terminé: {target}")
            
            vulns = result.get('vulnerabilities', [])
            high_severity = result.get('high_severity', 0)
            summary = f"Trouvé {len(vulns)} vulnérabilité(s), {high_severity} critiques"
            
            db.update_task_status(
                task_id=self.request.id,
                status='completed',
                progress=100,
                result_summary=summary
            )
        else:
            logger.error(f"❌ [Celery] Erreur scan vulnérabilités: {result.get('error')}")
            db.update_task_status(
                task_id=self.request.id,
                status='failed',
                error_message=result.get('error', 'Erreur scan vulnérabilités')
            )
            
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception scan vulnérabilités {target}: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        
        self.update_state(
            state='FAILURE',
            meta={
                'status': f'Erreur: {str(e)}',
                'target': target,
                'error': str(e)
            }
        )
        raise

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

# ===== UTILITAIRES =====
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

from celery_app import celery_app
from celery import current_task
import logging
import time
import subprocess
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
import re
import os

logger = logging.getLogger(__name__)

# ===== ACCÈS À LA BASE DE DONNÉES =====
def get_db_manager():
    """Accès au gestionnaire de base de données PostgreSQL uniquement"""
    try:
        import sys
        import os
        
        backend_path = os.path.join(os.path.dirname(__file__))
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        
        from database import DatabaseManager
        from config import config
        
        config_obj = config.get('development', config['default'])
        return DatabaseManager(config_obj.DATABASE_URL)
    except Exception as e:
        logger.error(f"❌ Erreur accès PostgreSQL dans Celery: {e}")
        return None

# ===== UTILITAIRES COMMUNES =====
def safe_subprocess_run(command: List[str], timeout: int = 300, **kwargs) -> subprocess.CompletedProcess:
    """Exécute une commande de façon sécurisée avec timeout"""
    try:
        logger.info(f"🔧 Exécution: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            **kwargs
        )
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"⏰ Timeout ({timeout}s) pour: {' '.join(command)}")
        raise
    except Exception as e:
        logger.error(f"❌ Erreur subprocess: {e}")
        raise

def update_task_progress(task_id: str, progress: int, status: str, phase: str = None):
    """Met à jour la progression d'une tâche"""
    db = get_db_manager()
    if db:
        try:
            db.update_task_status(
                task_id=task_id,
                status='running',
                progress=progress
            )
            
            # Utiliser self.update_state pour Celery si possible
            if current_task:
                meta = {
                    'status': status,
                    'progress': progress
                }
                if phase:
                    meta['phase'] = phase
                
                current_task.update_state(
                    state='PROGRESS',
                    meta=meta
                )
        except Exception as e:
            logger.error(f"❌ Erreur mise à jour progression: {e}")

def save_module_results(task_id: str, module_name: str, target: str, 
                       result_data: Dict, raw_output: str = None, 
                       scan_duration: int = None, stats: Dict = None):
    """Sauvegarde les résultats d'un module"""
    db = get_db_manager()
    if not db:
        logger.error("❌ Impossible de sauvegarder - pas de BDD")
        return False
    
    try:
        result_id = db.save_module_result(
            task_id=task_id,
            module_name=module_name,
            target=target,
            scan_type=module_name,
            result_data=result_data,
            raw_output=raw_output,
            scan_duration=scan_duration,
            stats=stats
        )
        logger.info(f"✅ Résultats sauvegardés: {module_name} (ID: {result_id})")
        return True
    except Exception as e:
        logger.error(f"❌ Erreur sauvegarde résultats {module_name}: {e}")
        return False

def finalize_task(task_id: str, success: bool, result_summary: str, 
                 error_message: str = None, result_data: Dict = None):
    """Finalise une tâche avec son statut final"""
    db = get_db_manager()
    if not db:
        return
    
    try:
        status = 'completed' if success else 'failed'
        progress = 100 if success else 0
        
        db.update_task_status(
            task_id=task_id,
            status=status,
            progress=progress,
            result_summary=result_summary,
            error_message=error_message
        )
        
        if success:
            logger.info(f"✅ Tâche terminée: {task_id} - {result_summary}")
        else:
            logger.error(f"❌ Tâche échouée: {task_id} - {error_message}")
            
    except Exception as e:
        logger.error(f"❌ Erreur finalisation tâche {task_id}: {e}")

def create_error_result(error_msg: str, target: str = None) -> Dict:
    """Crée un résultat d'erreur standardisé"""
    return {
        "success": False,
        "error": error_msg,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "results": {}
    }

def create_success_result(data: Dict, target: str = None, summary: str = None) -> Dict:
    """Crée un résultat de succès standardisé"""
    return {
        "success": True,
        "target": target,
        "summary": summary,
        "timestamp": datetime.now().isoformat(),
        "results": data
    }

def validate_target(target: str) -> bool:
    """Valide une cible (IP, réseau, URL)"""
    if not target or not target.strip():
        return False
    
    # Validation basique - peut être enrichie
    target = target.strip()
    
    # IP simple (192.168.1.1)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # Réseau CIDR (192.168.1.0/24)
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    
    # URL basique
    url_pattern = r'^https?://.+'
    
    if re.match(ip_pattern, target) or re.match(cidr_pattern, target) or re.match(url_pattern, target):
        return True
    
    # Hostname/domaine basique
    hostname_pattern = r'^[a-zA-Z0-9.-]+$'
    if re.match(hostname_pattern, target) and '.' in target:
        return True
    
    return False

def parse_nmap_output(nmap_output: str) -> Dict:
    """Parse la sortie Nmap basique - à enrichir selon les besoins"""
    results = {
        "hosts_found": [],
        "total_hosts": 0,
        "scan_info": {}
    }
    
    try:
        lines = nmap_output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Détection d'un nouvel hôte
            if "Nmap scan report for" in line:
                # Extract IP/hostname
                parts = line.split("Nmap scan report for ")
                if len(parts) > 1:
                    current_host = {
                        "target": parts[1].strip(),
                        "status": "unknown",
                        "ports": []
                    }
                    results["hosts_found"].append(current_host)
            
            # Statut de l'hôte
            elif "Host is up" in line and current_host:
                current_host["status"] = "up"
            
            # Ports ouverts (format: 22/tcp open ssh)
            elif current_host and "/" in line and ("open" in line or "closed" in line or "filtered" in line):
                port_info = line.strip()
                if port_info:
                    current_host["ports"].append(port_info)
        
        results["total_hosts"] = len([h for h in results["hosts_found"] if h.get("status") == "up"])
        
    except Exception as e:
        logger.error(f"❌ Erreur parsing Nmap: {e}")
        results["parse_error"] = str(e)
    
    return results

# ===== TÂCHE TEST EXISTANTE (conservée) =====
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

# ===== TEMPLATE POUR NOUVELLES TÂCHES DE PENTEST =====
def pentest_task_wrapper(task_func):
    """Décorateur pour standardiser les tâches de pentest"""
    def wrapper(self, *args, **kwargs):
        task_id = self.request.id
        db = get_db_manager()
        start_time = time.time()
        
        if not db:
            error_msg = "Impossible d'accéder à la base de données"
            logger.error(f"❌ {error_msg}")
            raise Exception(error_msg)
        
        try:
            # Exécuter la tâche
            result = task_func(self, *args, **kwargs)
            
            # Calculer la durée
            duration = int(time.time() - start_time)
            
            # Si la tâche retourne un résultat avec succès
            if isinstance(result, dict) and result.get('success'):
                finalize_task(
                    task_id=task_id,
                    success=True,
                    result_summary=result.get('summary', 'Tâche terminée avec succès')
                )
            
            return result
            
        except Exception as e:
            duration = int(time.time() - start_time)
            error_msg = str(e)
            logger.error(f"💥 Erreur dans tâche {task_func.__name__}: {error_msg}")
            
            finalize_task(
                task_id=task_id,
                success=False,
                result_summary='',
                error_message=error_msg
            )
            
            # Retourner un résultat d'erreur plutôt que lever l'exception
            # pour permettre à la chaîne de continuer
            return create_error_result(error_msg)
    
    return wrapper

# ===== UTILITAIRE POUR RÉCUPÉRER LE STATUT D'UNE TÂCHE =====
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

# ===== PLACEHOLDER POUR LES FUTURES TÂCHES DE PENTEST =====
# Les tâches suivantes seront implémentées dans les étapes 2.1 à 2.6 :
# - network_discovery (2.1)
# - port_scan (2.2) 
# - service_enumeration (2.3)
# - vulnerability_scan (2.4)
# - exploitation (2.5)
# - post_exploitation (2.6)

logger.info("🔧 Module tasks.py chargé avec structure commune pour pentest")

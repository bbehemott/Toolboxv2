from celery_app import celery_app
from celery import current_task
import logging
import time
from datetime import datetime
from typing import Dict, Any

# Import du wrapper HuntKit
from core.huntkit_tools import HuntKitIntegration

# Import des utilitaires existants
from tasks import (
    get_db_manager, update_task_progress, save_module_results, 
    finalize_task, create_error_result, create_success_result,
    pentest_task_wrapper
)

logger = logging.getLogger(__name__)

# ===== TÂCHES HUNTKIT =====

@celery_app.task(bind=True, name='tasks.huntkit_discovery')
@pentest_task_wrapper
def huntkit_network_discovery(self, target: str, options: Dict = None):
    """Découverte réseau avec Nmap (HuntKit)"""
    task_id = self.request.id
    options = options or {}
    
    try:
        logger.info(f"🌐 [HuntKit] Découverte réseau: {target}")
        
        # Initialiser HuntKit
        update_task_progress(task_id, 10, "Initialisation des outils HuntKit", "Initialisation")
        huntkit = HuntKitIntegration()
        
        # Vérifier les outils
        update_task_progress(task_id, 20, "Vérification des outils", "Vérification")
        tool_status = huntkit.get_tool_status()
        
        if not tool_status['tools_available']['nmap']:
            raise Exception("Nmap non disponible")
        
        # Lancer la découverte
        update_task_progress(task_id, 30, "Découverte des hôtes actifs", "Découverte réseau")
        start_time = time.time()
        
        discovery_result = huntkit.run_discovery(target)
        
        scan_duration = int(time.time() - start_time)
        
        if not discovery_result['success']:
            raise Exception(f"Échec découverte: {discovery_result.get('error', 'Erreur inconnue')}")
        
        # Progression selon les résultats
        hosts_found = discovery_result['summary']['hosts_discovered']
        update_task_progress(task_id, 70, f"Découverte terminée: {hosts_found} hôtes trouvés", "Analyse")
        
        # Analyser les résultats pour créer un résumé
        summary_data = {
            'target': target,
            'hosts_discovered': hosts_found,
            'scan_duration': scan_duration,
            'tool_used': 'nmap (HuntKit)',
            'success': True
        }
        
        # Sauvegarder en base
        update_task_progress(task_id, 90, "Sauvegarde des résultats", "Finalisation")
        
        save_module_results(
            task_id=task_id,
            module_name='discovery_huntkit',
            target=target,
            result_data=discovery_result,
            scan_duration=scan_duration,
            stats={'hosts_discovered': hosts_found}
        )
        
        # Finaliser
        update_task_progress(task_id, 100, "Découverte réseau terminée", "Terminé")
        
        result = create_success_result(
            data=discovery_result,
            target=target,
            summary=f"Découverte terminée: {hosts_found} hôtes trouvés en {scan_duration}s"
        )
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Erreur découverte HuntKit: {e}")
        return create_error_result(str(e), target)


@celery_app.task(bind=True, name='tasks.huntkit_web_audit')
@pentest_task_wrapper
def huntkit_web_audit(self, target: str, port: int = 80, ssl: bool = False, options: Dict = None):
    """Audit web avec Nikto + Nuclei + SQLMap (HuntKit)"""
    task_id = self.request.id
    options = options or {}
    
    try:
        logger.info(f"🕷️ [HuntKit] Audit web: {target}:{port}")
        
        # Initialiser HuntKit
        update_task_progress(task_id, 10, "Initialisation des outils web", "Initialisation")
        huntkit = HuntKitIntegration()
        
        # Vérifier les outils web
        update_task_progress(task_id, 20, "Vérification des outils", "Vérification")
        tool_status = huntkit.get_tool_status()
        
        required_tools = ['nikto', 'nuclei', 'sqlmap']
        missing_tools = [tool for tool in required_tools if not tool_status['tools_available'].get(tool)]
        
        if missing_tools:
            raise Exception(f"Outils manquants: {', '.join(missing_tools)}")
        
        # Lancer l'audit web
        update_task_progress(task_id, 30, "Début de l'audit web", "Scan web")
        start_time = time.time()
        
        audit_result = huntkit.run_web_audit(target, port, ssl)
        
        scan_duration = int(time.time() - start_time)
        
        if not audit_result['success']:
            raise Exception("Échec de l'audit web")
        
        # Analyser les résultats
        summary = audit_result['summary']
        total_vulns = summary['nikto_vulns'] + summary['nuclei_vulns']
        
        update_task_progress(task_id, 80, f"Audit terminé: {total_vulns} vulnérabilités trouvées", "Analyse")
        
        # Sauvegarder en base
        update_task_progress(task_id, 90, "Sauvegarde des résultats", "Finalisation")
        
        save_module_results(
            task_id=task_id,
            module_name='web_audit_huntkit',
            target=f"{target}:{port}",
            result_data=audit_result,
            scan_duration=scan_duration,
            stats={
                'vulnerabilities_found': total_vulns,
                'severity_high': summary['nuclei_vulns']  # Approximation
            }
        )
        
        # Finaliser
        update_task_progress(task_id, 100, "Audit web terminé", "Terminé")
        
        result = create_success_result(
            data=audit_result,
            target=f"{target}:{port}",
            summary=f"Audit web terminé: {total_vulns} vulnérabilités trouvées"
        )
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Erreur audit web HuntKit: {e}")
        return create_error_result(str(e), f"{target}:{port}")


@celery_app.task(bind=True, name='tasks.huntkit_brute_force')
@pentest_task_wrapper
def huntkit_brute_force(self, target: str, service: str, username: str = None, 
                       userlist: str = None, passwordlist: str = None, options: Dict = None):
    """Force brute avec Hydra (HuntKit)"""
    task_id = self.request.id
    options = options or {}
    
    try:
        logger.info(f"🔨 [HuntKit] Force brute: {target} ({service})")
        
        # Initialiser HuntKit
        update_task_progress(task_id, 10, "Initialisation de Hydra", "Initialisation")
        huntkit = HuntKitIntegration()
        
        # Vérifier Hydra
        update_task_progress(task_id, 20, "Vérification de Hydra", "Vérification")
        tool_status = huntkit.get_tool_status()
        
        if not tool_status['tools_available']['hydra']:
            raise Exception("Hydra non disponible")
        
        # Lancer l'attaque
        update_task_progress(task_id, 30, f"Début force brute sur {service}", "Force brute")
        start_time = time.time()
        
        brute_result = huntkit.run_brute_force(
            target=target,
            service=service,
            userlist=userlist,
            passwordlist=passwordlist
        )
        
        scan_duration = int(time.time() - start_time)
        
        if not brute_result['success']:
            raise Exception("Échec de l'attaque par force brute")
        
        # Analyser les résultats
        credentials_found = len(brute_result['credentials_found'])
        
        if credentials_found > 0:
            update_task_progress(task_id, 80, f"Succès: {credentials_found} credential(s) trouvé(s)", "Succès")
        else:
            update_task_progress(task_id, 80, "Aucun credential trouvé", "Terminé")
        
        # Sauvegarder en base
        update_task_progress(task_id, 90, "Sauvegarde des résultats", "Finalisation")
        
        save_module_results(
            task_id=task_id,
            module_name='brute_force_huntkit',
            target=f"{target}:{service}",
            result_data=brute_result,
            scan_duration=scan_duration,
            stats={'credentials_found': credentials_found}
        )
        
        # Finaliser
        update_task_progress(task_id, 100, "Force brute terminé", "Terminé")
        
        result = create_success_result(
            data=brute_result,
            target=f"{target}:{service}",
            summary=f"Force brute terminé: {credentials_found} credential(s) trouvé(s)"
        )
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Erreur force brute HuntKit: {e}")
        return create_error_result(str(e), f"{target}:{service}")


@celery_app.task(bind=True, name='tasks.huntkit_full_scan')
@pentest_task_wrapper
def huntkit_full_pentest(self, target: str, options: Dict = None):
    """Pentest complet avec tous les outils HuntKit"""
    task_id = self.request.id
    options = options or {}
    
    try:
        logger.info(f"🎯 [HuntKit] Pentest complet: {target}")
        
        results = {
            'target': target,
            'started_at': datetime.now().isoformat(),
            'phases': {}
        }
        
        # Phase 1: Découverte réseau
        update_task_progress(task_id, 10, "Phase 1: Découverte réseau", "Découverte")
        discovery_task = huntkit_network_discovery.apply_async(args=[target])
        discovery_result = discovery_task.get(timeout=600)  # 10 min max
        results['phases']['discovery'] = discovery_result
        
        if not discovery_result.get('success'):
            raise Exception("Échec de la découverte réseau")
        
        # Phase 2: Audit web (si port 80/443 ouvert)
        update_task_progress(task_id, 40, "Phase 2: Audit web", "Audit web")
        
        # Chercher les ports web dans les résultats de découverte
        web_ports = []
        port_scans = discovery_result.get('results', {}).get('port_scans', [])
        
        for scan in port_scans[:3]:  # Max 3 hôtes
            # Analyser les ports ouverts (parsing basique)
            if '80' in str(scan) or '443' in str(scan) or '8080' in str(scan):
                web_ports.append({'host': scan.get('host', target), 'port': 80})
        
        if web_ports:
            web_results = []
            for web_target in web_ports[:2]:  # Max 2 cibles web
                web_task = huntkit_web_audit.apply_async(
                    args=[web_target['host'], web_target['port']]
                )
                web_result = web_task.get(timeout=900)  # 15 min max
                web_results.append(web_result)
            results['phases']['web_audit'] = web_results
        
        # Phase 3: Force brute sur SSH (si port 22 ouvert)
        update_task_progress(task_id, 70, "Phase 3: Force brute SSH", "Force brute")
        
        # Chercher le port SSH
        ssh_targets = []
        for scan in port_scans[:2]:  # Max 2 hôtes
            if '22' in str(scan):
                ssh_targets.append(scan.get('host', target))
        
        if ssh_targets:
            brute_results = []
            for ssh_target in ssh_targets[:1]:  # Max 1 cible SSH
                brute_task = huntkit_brute_force.apply_async(
                    args=[ssh_target, 'ssh']
                )
                brute_result = brute_task.get(timeout=1800)  # 30 min max
                brute_results.append(brute_result)
            results['phases']['brute_force'] = brute_results
        
        # Finaliser
        update_task_progress(task_id, 90, "Génération du rapport final", "Finalisation")
        
        results['completed_at'] = datetime.now().isoformat()
        results['success'] = True
        
        # Statistiques globales
        total_vulns = 0
        total_credentials = 0
        
        for phase_name, phase_data in results['phases'].items():
            if isinstance(phase_data, list):
                for item in phase_data:
                    if 'summary' in item:
                        total_vulns += item['summary'].get('nikto_vulns', 0)
                        total_vulns += item['summary'].get('nuclei_vulns', 0)
                        total_credentials += len(item.get('credentials_found', []))
            elif isinstance(phase_data, dict) and 'summary' in phase_data:
                total_vulns += phase_data['summary'].get('hosts_discovered', 0)
        
        # Sauvegarder le rapport complet
        save_module_results(
            task_id=task_id,
            module_name='full_pentest_huntkit',
            target=target,
            result_data=results,
            scan_duration=int((datetime.fromisoformat(results['completed_at']) - 
                             datetime.fromisoformat(results['started_at'])).total_seconds()),
            stats={
                'total_vulnerabilities': total_vulns,
                'credentials_found': total_credentials
            }
        )
        
        update_task_progress(task_id, 100, "Pentest complet terminé", "Terminé")
        
        return create_success_result(
            data=results,
            target=target,
            summary=f"Pentest complet terminé: {total_vulns} vulnérabilités, {total_credentials} credentials"
        )
        
    except Exception as e:
        logger.error(f"❌ Erreur pentest complet HuntKit: {e}")
        return create_error_result(str(e), target)


@celery_app.task(bind=True, name='tasks.huntkit_tools_check')
def huntkit_tools_verification(self):
    """Vérification de l'état des outils HuntKit"""
    task_id = self.request.id
    
    try:
        logger.info("🔧 [HuntKit] Vérification des outils")
        
        huntkit = HuntKitIntegration()
        tool_status = huntkit.get_tool_status()
        
        # Compter les outils disponibles
        available_tools = sum(1 for available in tool_status['tools_available'].values() if available)
        total_tools = len(tool_status['tools_available'])
        
        result = {
            'success': True,
            'tools_status': tool_status,
            'summary': f"{available_tools}/{total_tools} outils disponibles",
            'all_tools_ready': available_tools == total_tools
        }
        
        # Sauvegarder le statut
        save_module_results(
            task_id=task_id,
            module_name='tools_verification',
            target='localhost',
            result_data=result
        )
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Erreur vérification outils: {e}")
        return create_error_result(str(e), 'localhost')


logger.info("🔧 Module HuntKit tasks chargé avec 5 nouvelles tâches")

from celery_app import celery_app
from celery import current_task
import logging
import time
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

# ===== ACCÈS À LA BASE DE DONNÉES =====
def get_db_manager():
    """Accès simplifié au gestionnaire de base de données - VERSION CORRIGÉE"""
    try:
        import sys
        import os
        
        # CORRECTION: Ajouter le répertoire courant au PATH
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)
        
        from database import DatabaseManager
        from config import config
        
        config_obj = config.get('development', config['default'])
        db_manager = DatabaseManager(config_obj.DATABASE_PATH)
        
        logger.info(f"✅ Connexion BDD réussie dans Celery: {config_obj.DATABASE_PATH}")
        return db_manager
        
    except ImportError as e:
        logger.error(f"❌ Erreur import dans Celery: {e}")
        logger.error(f"❌ Python path: {sys.path}")
        logger.error(f"❌ Current dir: {os.getcwd()}")
        return None
    except Exception as e:
        logger.error(f"❌ Erreur accès BDD dans Celery: {e}")
        return None

# ===== TÂCHE TEST (existante) =====
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

# ===== TÂCHE EXEMPLE (existante) =====
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

# ===== NOUVELLES TÂCHES PENTEST =====

@celery_app.task(bind=True, name='tasks.network_discovery')
def network_discovery(self, target: str, options: Dict = None):
    """Tâche Celery pour la découverte réseau"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        start_time = time.time()
        logger.info(f"🌐 [Celery] Découverte réseau démarrée: {target}")
        
        # Mise à jour du statut initial
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Initialisation de la découverte réseau...',
                'progress': 5,
                'target': target,
                'phase': 'Initialisation'
            }
        )
        
        # Validation des options
        if not options:
            options = {}
        
        # Créer l'instance de l'outil
        from modules.network_discovery import NetworkDiscoveryTool
        discovery_tool = NetworkDiscoveryTool()
        
        # Validation de la cible
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Validation de la cible: {target}',
                'progress': 10,
                'target': target,
                'phase': 'Validation'
            }
        )
        
        is_valid, validation_msg = discovery_tool.validate_target(target)
        if not is_valid:
            error_msg = f"Cible invalide: {validation_msg}"
            logger.error(f"❌ [Celery] {error_msg}")
            
            db.update_task_status(
                task_id=self.request.id,
                status='failed',
                error_message=error_msg
            )
            raise Exception(error_msg)
        
        # Début de la découverte
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Lancement de la découverte (Nmap)...',
                'progress': 20,
                'target': target,
                'phase': 'Découverte réseau'
            }
        )
        
        # Exécution de la découverte
        discovery_result = discovery_tool.discover_network(target, options)
        
        # Mise à jour du statut durant la découverte
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Analyse des résultats...',
                'progress': 80,
                'target': target,
                'phase': 'Analyse des résultats'
            }
        )
        
        # Vérification du succès
        if not discovery_result.get('success', False):
            error_msg = discovery_result.get('error', 'Erreur inconnue lors de la découverte')
            logger.error(f"❌ [Celery] Découverte échouée: {error_msg}")
            
            db.update_task_status(
                task_id=self.request.id,
                status='failed',
                error_message=error_msg
            )
            raise Exception(error_msg)
        
        # Préparation du résultat final
        hosts_found = discovery_result.get('hosts_found', 0)
        
        # Génération du résumé avec statistiques détaillées
        summary_parts = []
        summary_parts.append(f"{hosts_found} hôte(s) découvert(s)")
        
        if hosts_found > 0:
            hosts_with_ports = len([h for h in discovery_result.get('hosts', []) if h.get('ports')])
            total_ports = sum(len(h.get('ports', [])) for h in discovery_result.get('hosts', []))
            
            if hosts_with_ports > 0:
                summary_parts.append(f"{hosts_with_ports} avec ports ouverts")
                summary_parts.append(f"{total_ports} ports détectés")
            
            # Analyse des types de services détectés
            services_found = set()
            for host in discovery_result.get('hosts', []):
                for port in host.get('ports', []):
                    if port.get('port'):
                        services_found.add(port['port'])
            
            # Calculer des métriques supplémentaires pour le résumé
            discovery_result['summary'] = {
                'total_hosts_found': hosts_found,
                'hosts_with_open_ports': hosts_with_ports,
                'total_open_ports': total_ports,
                'unique_ports_found': list(services_found),
                'most_common_ports': {},
                'potential_servers': []
            }
            
            # Ports les plus fréquents
            port_count = {}
            server_indicators = {
                80: 'Web Server',
                443: 'HTTPS Server', 
                22: 'SSH Server',
                21: 'FTP Server',
                25: 'SMTP Server',
                53: 'DNS Server',
                3389: 'RDP Server',
                445: 'SMB Server'
            }
            
            for host in discovery_result.get('hosts', []):
                for port in host.get('ports', []):
                    port_num = port.get('port')
                    if port_num:
                        port_count[port_num] = port_count.get(port_num, 0) + 1
            
            # Top 5 des ports les plus fréquents
            top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:5]
            discovery_result['summary']['most_common_ports'] = dict(top_ports)
            
            # Identifier les serveurs potentiels
            for host in discovery_result.get('hosts', []):
                server_types = []
                host_ports = [p.get('port') for p in host.get('ports', []) if p.get('port')]
                
                for port in host_ports:
                    if port in server_indicators:
                        server_types.append(server_indicators[port])
                
                if server_types:
                    discovery_result['summary']['potential_servers'].append({
                        'ip': host.get('ip'),
                        'type': ', '.join(server_types),
                        'ports': host_ports
                    })
        
        result_summary = ", ".join(summary_parts)
        
        # Finalisation
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Sauvegarde des résultats...',
                'progress': 95,
                'target': target,
                'phase': 'Finalisation'
            }
        )
        
        # Structurer le résultat final
        final_result = {
            'task_id': self.request.id,
            'module': 'Découverte Réseau',
            'target': target,
            'method': 'nmap',
            'success': True,
            'scan_duration': discovery_result.get('duration_seconds', 0),
            'hosts_found': hosts_found,
            'result_data': discovery_result,
            'completed_at': discovery_result.get('scan_end')
        }
        
        # Sauvegarde en base
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=result_summary
        )
        
        # Sauvegarder les résultats détaillés
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='network_discovery',
                    result_data=final_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder les résultats détaillés: {save_error}")
        
        logger.info(f"✅ [Celery] Découverte réseau terminée: {result_summary}")
        
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception découverte réseau: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

@celery_app.task(bind=True, name='tasks.port_scan')
def port_scan(self, hosts_data: Dict, options: Dict = None):
    """Tâche Celery pour le scan de ports sur les hôtes découverts"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🔍 [Celery] Scan de ports démarré")
        
        # Extraction des hôtes depuis les données de découverte
        if isinstance(hosts_data, dict) and 'result_data' in hosts_data:
            hosts = hosts_data['result_data'].get('hosts', [])
            target = hosts_data.get('target', 'Unknown')
        elif isinstance(hosts_data, dict) and 'hosts' in hosts_data:
            hosts = hosts_data['hosts']
            target = hosts_data.get('target', 'Unknown')
        else:
            # Si c'est juste une IP passée directement
            if isinstance(hosts_data, str):
                hosts = [{'ip': hosts_data}]
                target = hosts_data
            else:
                hosts = []
                target = 'Unknown'
        
        if not hosts:
            raise Exception("Aucun hôte trouvé pour le scan de ports")
        
        # Mise à jour du statut
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Début scan de ports sur {len(hosts)} hôte(s)',
                'progress': 10,
                'target': target,
                'phase': 'Scan ports'
            }
        )
        
        # Import de l'outil de scan de ports
        port_scanner = PortScanner()
        
        # Scan des ports pour chaque hôte
        results = []
        total_hosts = len(hosts)
        total_open_ports = 0
        total_services = 0
        
        for i, host in enumerate(hosts):
            host_ip = host.get('ip')
            if not host_ip:
                continue
            
            progress = 20 + (i * 60 // total_hosts)
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Scan ports sur {host_ip} ({i+1}/{total_hosts})',
                    'progress': progress,
                    'target': target,
                    'phase': 'Scan ports'
                }
            )
            
            # Scan de l'hôte
            host_result = port_scanner.scan_host_ports(host_ip, options)
            results.append(host_result)
            
            # Compteurs pour statistiques
            if host_result.get('success'):
                total_open_ports += len(host_result.get('open_ports', []))
                total_services += len(host_result.get('services', []))
        
        # Compilation des résultats
        hosts_with_ports = len([r for r in results if r.get('open_ports')])
        successful_scans = len([r for r in results if r.get('success')])
        
        # Analyser les services trouvés
        all_services = {}
        for result in results:
            for service in result.get('services', []):
                service_name = service.get('service', 'unknown')
                if service_name not in all_services:
                    all_services[service_name] = 0
                all_services[service_name] += 1
        
        final_result = {
            'task_id': self.request.id,
            'module': 'Scan Ports',
            'target': target,
            'success': True,
            'hosts_scanned': len(results),
            'successful_scans': successful_scans,
            'total_open_ports': total_open_ports,
            'total_services': total_services,
            'hosts_with_open_ports': hosts_with_ports,
            'service_summary': all_services,
            'results': results,
            'scan_options': options or {}
        }
        
        summary = f"{successful_scans}/{len(results)} hôtes scannés, {hosts_with_ports} avec ports ouverts, {total_open_ports} ports total"
        
        # Finalisation
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Sauvegarde des résultats...',
                'progress': 95,
                'target': target,
                'phase': 'Finalisation'
            }
        )
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary
        )
        
        # Sauvegarder les résultats détaillés
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='port_scan',
                    result_data=final_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder les résultats détaillés: {save_error}")
        
        logger.info(f"✅ [Celery] Scan de ports terminé: {summary}")
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception scan ports: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

@celery_app.task(bind=True, name='tasks.service_enumeration')
def service_enumeration(self, hosts_data: Dict, options: Dict = None):
    """Tâche Celery pour l'énumération détaillée des services"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🔧 [Celery] Énumération de services démarrée")
        
        # Extraction des données des hôtes avec ports
        if isinstance(hosts_data, dict) and 'results' in hosts_data:
            host_results = hosts_data['results']
            target = hosts_data.get('target', 'Multiple hosts')
        else:
            raise Exception("Données d'hôtes invalides pour l'énumération")
        
        # Filtrer seulement les hôtes avec des ports ouverts
        hosts_with_ports = [h for h in host_results if h.get('success') and h.get('open_ports')]
        
        if not hosts_with_ports:
            raise Exception("Aucun hôte avec ports ouverts trouvé pour l'énumération")
        
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Énumération sur {len(hosts_with_ports)} hôte(s)',
                'progress': 10,
                'target': target,
                'phase': 'Énumération services'
            }
        )
        
        # Pour chaque hôte, faire une énumération détaillée
        enumeration_results = []
        
        for i, host_data in enumerate(hosts_with_ports):
            host_ip = host_data.get('host')
            open_ports = host_data.get('open_ports', [])
            
            progress = 20 + (i * 60 // len(hosts_with_ports))
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Énumération {host_ip} ({i+1}/{len(hosts_with_ports)})',
                    'progress': progress,
                    'target': target,
                    'phase': 'Énumération services'
                }
            )
            
            # Énumération détaillée par port
            host_enum_result = {
                'host': host_ip,
                'enumerated_services': [],
                'additional_info': [],
                'vulnerabilities_hints': []
            }
            
            for port_info in open_ports:
                port_num = port_info.get('port')
                service_name = port_info.get('service_info', {}).get('service', 'unknown')
                
                # Simuler une énumération plus détaillée selon le service
                enum_info = {
                    'port': port_num,
                    'service': service_name,
                    'detailed_info': {},
                    'scripts_run': []
                }
                
                # Exemples d'énumération selon le service
                if service_name in ['http', 'https'] or port_num in [80, 443, 8080]:
                    enum_info['detailed_info'] = {
                        'server_header': 'Apache/2.4.41',
                        'technologies': ['PHP', 'MySQL'],
                        'directories_found': ['/admin', '/backup', '/uploads'],
                        'forms_detected': True
                    }
                    enum_info['scripts_run'] = ['http-enum', 'http-title', 'http-methods']
                    
                elif service_name == 'ssh' or port_num == 22:
                    enum_info['detailed_info'] = {
                        'ssh_version': 'OpenSSH 7.4',
                        'auth_methods': ['password', 'publickey'],
                        'algorithms': ['aes128-ctr', 'aes192-ctr']
                    }
                    enum_info['scripts_run'] = ['ssh-auth-methods', 'ssh-hostkey']
                    
                elif service_name in ['smb', 'netbios-ssn'] or port_num in [139, 445]:
                    enum_info['detailed_info'] = {
                        'smb_version': 'SMBv2',
                        'shares_found': ['IPC$', 'C$', 'ADMIN$'],
                        'os_info': 'Windows Server 2016'
                    }
                    enum_info['scripts_run'] = ['smb-enum-shares', 'smb-os-discovery']
                
                host_enum_result['enumerated_services'].append(enum_info)
            
            enumeration_results.append(host_enum_result)
        
        # Compilation des résultats
        total_services_enumerated = sum(len(h['enumerated_services']) for h in enumeration_results)
        
        final_result = {
            'task_id': self.request.id,
            'module': 'Énumération Services',
            'target': target,
            'success': True,
            'hosts_enumerated': len(enumeration_results),
            'total_services': total_services_enumerated,
            'enumeration_results': enumeration_results
        }
        
        summary = f"{len(enumeration_results)} hôtes énumérés, {total_services_enumerated} services détaillés"
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary
        )
        
        # Sauvegarder les résultats
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='service_enumeration',
                    result_data=final_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder les résultats: {save_error}")
        
        logger.info(f"✅ [Celery] Énumération services terminée: {summary}")
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception énumération services: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

@celery_app.task(bind=True, name='tasks.full_network_audit')
def full_network_audit(self, target: str, options: Dict = None):
    """Tâche maîtresse qui orchestre toute la découverte réseau + scan ports + énumération"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        start_time = time.time()
        logger.info(f"🎯 [Celery] Audit réseau complet démarré sur: {target}")
        
        # Mise à jour du statut initial
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        if not options:
            options = {}
        
        # Phase 1: Découverte réseau
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Phase 1/3: Découverte réseau...',
                'progress': 5,
                'target': target,
                'phase': 'Découverte réseau'
            }
        )
        
        # Lancer la découverte réseau directement
        discovery_options = {
            'method': options.get('discovery_method', 'nmap'),
            'timing': options.get('timing', 'T4'),
            'no_ping': options.get('no_ping', False),
            'arp_ping': options.get('arp_ping', False)
        }
        
        from modules.network_discovery import NetworkDiscoveryTool
        discovery_tool = NetworkDiscoveryTool()
        discovery_result = discovery_tool.discover_network(target, discovery_options)


        if not discovery_result.get('success'):
            raise Exception(f"Échec découverte réseau: {discovery_result.get('error', 'Erreur inconnue')}")

        
        hosts_found = discovery_result.get('hosts_found', 0)
        if hosts_found == 0:
            raise Exception("Aucun hôte découvert - arrêt de l'audit")
        
        # Phase 2: Scan de ports
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Phase 2/3: Scan de ports sur {hosts_found} hôte(s)...',
                'progress': 35,
                'target': target,
                'phase': 'Scan ports'
            }
        )
        
        port_options = {
            'ports': options.get('port_range', 'top_1000'),
            'timing': options.get('timing', 'T4'),
            'service_detection': options.get('service_detection', True),
            'os_detection': options.get('os_detection', False)
        }
        
        port_scanner = PortScanner()

        hosts = discovery_result.get('hosts', [])
        if hosts:
            port_results = []
            total_hosts = len(hosts)
    
            for i, host in enumerate(hosts):
                # Mettre à jour la progression
                progress = 35 + (i * 35 // total_hosts)  # Entre 35% et 70%
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'Scan ports {host.get("ip")} ({i+1}/{total_hosts})',
                        'progress': progress,
                        'target': target,
                        'phase': 'Scan ports'
                    }
                )
        
                result = port_scanner.scan_host_ports(host.get('ip'), port_options)
                port_results.append(result)
    
            # Compiler les résultats
            successful_scans = len([r for r in port_results if r.get('success')])
            total_open_ports = sum(len(r.get('open_ports', [])) for r in port_results)
            total_services = sum(len(r.get('services', [])) for r in port_results)
            hosts_with_ports = len([r for r in port_results if r.get('open_ports')])
    
            port_scan_result = {
                'success': True,
                'results': port_results,
                'target': target,
                'hosts_scanned': len(port_results),
                'successful_scans': successful_scans,
                'total_open_ports': total_open_ports,
                'total_services': total_services,
                'hosts_with_open_ports': hosts_with_ports
            }
        else:
            port_scan_result = {'success': False, 'error': 'Aucun hôte découvert pour le scan de ports'}

        if not port_scan_result.get('success'):
            logger.warning(f"⚠️ Scan de ports échoué: {port_scan_result.get('error')}")

        
        # Phase 3: Énumération (si activée et si des ports ont été trouvés)
        enumeration_result = None
        if options.get('deep_scan', False) and port_scan_result.get('hosts_with_open_ports', 0) > 0:
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': 'Phase 3/3: Énumération des services...',
                    'progress': 70,
                    'target': target,
                    'phase': 'Énumération services'
                }
            )
            
            enumeration_result = {
                'success': True,
                'hosts_enumerated': port_scan_result.get('hosts_with_open_ports', 0),
                'total_services': port_scan_result.get('total_open_ports', 0),
                'target': target
            }
        
        # Compilation des résultats de toutes les phases
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Finalisation de l\'audit...',
                'progress': 95,
                'target': target,
                'phase': 'Finalisation'
            }
        )
        
        # Résumé global de l'audit
        total_hosts = discovery_result.get('hosts_found', 0)
        hosts_with_ports = port_scan_result.get('hosts_with_open_ports', 0)
        total_ports = port_scan_result.get('total_open_ports', 0)
        total_services = port_scan_result.get('total_services', 0)
        
        phases_completed = ['discovery', 'port_scan']
        if enumeration_result:
            phases_completed.append('service_enumeration')
        
        audit_summary = {
            'task_id': self.request.id,
            'target': target,
            'audit_complete': True,
            'phases_completed': phases_completed,
            'discovery_results': discovery_result,
            'port_scan_results': port_scan_result,
            'enumeration_results': enumeration_result,
            'summary': {
                'total_hosts': total_hosts,
                'hosts_with_ports': hosts_with_ports,
                'total_ports': total_ports,
                'total_services': total_services,
                'scan_duration': time.time() - start_time
            }
        }
        
        # Résumé textuel
        summary_text = f"Audit complet terminé: {total_hosts} hôtes, {hosts_with_ports} avec ports ouverts, {total_ports} ports trouvés"
        
        # Finaliser la tâche
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary_text
        )
        
        # Sauvegarder le résumé de l'audit
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='full_audit',
                    result_data=audit_summary
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder le résumé d'audit: {save_error}")
        
        logger.info(f"🎯 [Celery] Audit complet terminé: {summary_text}")
        return audit_summary
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception audit complet: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

@celery_app.task(bind=True, name='tasks.vulnerability_scan')
def vulnerability_scan(self, hosts_data: Dict, options: Dict = None):
    """Tâche Celery pour le scan de vulnérabilités avec Nuclei"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"🚨 [Celery] Scan de vulnérabilités démarré")
        
        # Extraction des hôtes avec services
        if isinstance(hosts_data, dict) and 'results' in hosts_data:
            host_results = hosts_data['results']
            target = hosts_data.get('target', 'Multiple hosts')
        else:
            raise Exception("Données d'hôtes invalides pour le scan de vulnérabilités")
        
        # Filtrer seulement les hôtes avec des services détectés
        hosts_with_services = [h for h in host_results if h.get('success') and h.get('services')]
        
        if not hosts_with_services:
            raise Exception("Aucun service trouvé pour le scan de vulnérabilités")
        
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Scan vulnérabilités sur {len(hosts_with_services)} hôte(s)',
                'progress': 10,
                'target': target,
                'phase': 'Scan vulnérabilités'
            }
        )
        
        # Simuler le scan de vulnérabilités
        vulnerabilities_found = []
        total_scanned = 0
        
        for i, host_data in enumerate(hosts_with_services):
            host_ip = host_data.get('host')
            services = host_data.get('services', [])
            
            progress = 20 + (i * 60 // len(hosts_with_services))
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Scan vulnérabilités {host_ip} ({i+1}/{len(hosts_with_services)})',
                    'progress': progress,
                    'target': target,
                    'phase': 'Scan vulnérabilités'
                }
            )
            
            # Simuler la détection de vulnérabilités par service
            for service in services:
                total_scanned += 1
                
                # Exemples de vulnérabilités basées sur les services
                if service.get('service') == 'http' or service.get('port') in [80, 8080]:
                    vulnerabilities_found.append({
                        'host': host_ip,
                        'port': service.get('port'),
                        'service': service.get('service'),
                        'vulnerability': 'HTTP Information Disclosure',
                        'severity': 'Medium',
                        'description': 'Server header reveals version information',
                        'cvss': 5.3
                    })
                elif service.get('service') == 'ssh' or service.get('port') == 22:
                    vulnerabilities_found.append({
                        'host': host_ip,
                        'port': service.get('port'),
                        'service': service.get('service'),
                        'vulnerability': 'SSH Weak Algorithms',
                        'severity': 'Low',
                        'description': 'SSH server supports weak encryption algorithms',
                        'cvss': 2.6
                    })
        
        # Résultats finaux
        final_result = {
            'task_id': self.request.id,
            'module': 'Scan Vulnérabilités',
            'target': target,
            'success': True,
            'hosts_scanned': len(hosts_with_services),
            'services_scanned': total_scanned,
            'vulnerabilities_found': len(vulnerabilities_found),
            'vulnerabilities': vulnerabilities_found,
            'scan_options': options or {}
        }
        
        summary = f"{len(vulnerabilities_found)} vulnérabilité(s) trouvée(s) sur {len(hosts_with_services)} hôte(s)"
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary
        )
        
        # Sauvegarder les résultats
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='vulnerability_scan',
                    result_data=final_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder les résultats: {save_error}")
        
        logger.info(f"✅ [Celery] Scan vulnérabilités terminé: {summary}")
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception scan vulnérabilités: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

@celery_app.task(bind=True, name='tasks.exploitation')
def exploitation(self, vulnerabilities_data: Dict, options: Dict = None):
    """Tâche Celery pour l'exploitation automatisée"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        logger.info(f"💥 [Celery] Exploitation démarrée")
        
        vulnerabilities = vulnerabilities_data.get('vulnerabilities', [])
        target = vulnerabilities_data.get('target', 'Multiple targets')
        
        if not vulnerabilities:
            raise Exception("Aucune vulnérabilité à exploiter")
        
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        # Tentatives d'exploitation
        exploitation_results = []
        credentials_found = []
        
        for i, vuln in enumerate(vulnerabilities):
            progress = 10 + (i * 80 // len(vulnerabilities))
            
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Exploitation {vuln["host"]}:{vuln["port"]} ({i+1}/{len(vulnerabilities)})',
                    'progress': progress,
                    'target': target,
                    'phase': 'Exploitation'
                }
            )
            
            # Simuler l'exploitation selon le type de vulnérabilité
            exploit_result = {
                'host': vuln['host'],
                'port': vuln['port'],
                'vulnerability': vuln['vulnerability'],
                'exploit_attempted': True,
                'exploit_successful': False,
                'method': 'Automated',
                'output': ''
            }
            
            # Simulation d'exploitation réussie pour certains cas
            if vuln['severity'] in ['High', 'Critical'] and vuln['cvss'] > 7.0:
                exploit_result['exploit_successful'] = True
                exploit_result['output'] = f"Successful exploitation of {vuln['vulnerability']}"
                
                # Simulation de récupération de credentials
                if 'authentication' in vuln['vulnerability'].lower():
                    credentials_found.append({
                        'host': vuln['host'],
                        'service': vuln['service'],
                        'username': 'admin',
                        'password': 'password123',
                        'method': 'Brute force'
                    })
            
            exploitation_results.append(exploit_result)
        
        # Résultats finaux
        successful_exploits = [r for r in exploitation_results if r['exploit_successful']]
        
        final_result = {
            'task_id': self.request.id,
            'module': 'Exploitation',
            'target': target,
            'success': True,
            'vulnerabilities_tested': len(vulnerabilities),
            'exploits_attempted': len(exploitation_results),
            'successful_exploits': len(successful_exploits),
            'credentials_found': credentials_found,
            'exploitation_results': exploitation_results
        }
        
        summary = f"{len(successful_exploits)}/{len(vulnerabilities)} exploitation(s) réussie(s), {len(credentials_found)} credential(s) trouvé(s)"
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary
        )
        
        # Sauvegarder les résultats
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='exploitation',
                    result_data=final_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder les résultats: {save_error}")
        
        logger.info(f"✅ [Celery] Exploitation terminée: {summary}")
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception exploitation: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise



@celery_app.task(bind=True, name='tasks.enhanced_port_scan')
def enhanced_port_scan(self, target: str, options: Dict = None, escalation_config: Dict = None):


    """Tâche Celery pour le scan de ports avec escalade automatique"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        from modules.port_scanner import PortScanner

        start_time = time.time()
        logger.info(f"🔍 [Celery] Scan ports amélioré démarré: {target}")
        
        # Mise à jour du statut initial
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        # Configuration par défaut
        if not options:
            options = {}
        
        if not escalation_config:
            escalation_config = {
                'auto_escalate': True,
                'max_auto_level': 2,
                'ask_user_above': True
            }
        
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Initialisation du scan ports amélioré...',
                'progress': 5,
                'target': target,
                'phase': 'Initialisation',
                'escalation_enabled': escalation_config.get('auto_escalate', False)
            }
        )
        
        # Import du scanner amélioré
        port_scanner = PortScanner()
        
        # Métadonnées d'escalade
        escalation_history = []
        current_level = 1
        
        # Callback pour mettre à jour le statut durant l'escalade
        def escalation_callback(level_info):
            nonlocal current_level
            current_level = level_info['level']
            
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f"Niveau {level_info['level']}: {level_info['preset_name']}",
                    'progress': 20 + (level_info['level'] * 15),
                    'target': target,
                    'phase': f"Escalade niveau {level_info['level']}",
                    'current_preset': level_info['preset_name'],
                    'escalation_history': escalation_history
                }
            )
            
            escalation_history.append({
                'level': level_info['level'],
                'preset': level_info['preset_name'],
                'started_at': time.time(),
                'status': 'running'
            })
        
        # Exécution du scan avec escalade
        result = port_scanner.scan_host_ports(
            target, 
            options, 
            escalation_config
        )
        
        # Mise à jour finale
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Finalisation des résultats...',
                'progress': 90,
                'target': target,
                'phase': 'Finalisation'
            }
        )
        
        # Enrichir les résultats
        if result.get('success'):
            ports_found = len(result.get('open_ports', []))
            services_found = len(result.get('services', []))
            
            # Résumé selon escalade
            if result.get('escalation_used'):
                final_level = result.get('final_level', 1)
                summary = f"Escalade niveau {final_level}: {ports_found} ports, {services_found} services"
            else:
                summary = f"Scan simple: {ports_found} ports, {services_found} services"
            
            # Recommandations selon les résultats
            recommendations = []
            if ports_found == 0 and not result.get('escalation_used'):
                recommendations.append("Aucun port trouvé - Essayez un scan plus approfondi")
            elif ports_found > 0:
                recommendations.append(f"Services détectés - Procédez à l'énumération")
        else:
            summary = f"Échec du scan: {result.get('error', 'Erreur inconnue')}"
            recommendations = ["Vérifiez la connectivité réseau"]
        
        # Résultat final structuré
        final_result = {
            'task_id': self.request.id,
            'module': 'Scan Ports Amélioré',
            'target': target,
            'success': result.get('success', False),
            'scan_duration': time.time() - start_time,
            'escalation_used': result.get('escalation_used', False),
            'final_level': result.get('final_level', 1),
            'ports_found': len(result.get('open_ports', [])),
            'services_found': len(result.get('services', [])),
            'result_data': result,
            'recommendations': recommendations,
            'escalation_config': escalation_config
        }
        
        # Finalisation
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary
        )
        
        # Sauvegarder les résultats détaillés
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='enhanced_port_scan',
                    result_data=final_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder les résultats détaillés: {save_error}")
        
        logger.info(f"✅ [Celery] Scan ports amélioré terminé: {summary}")
        
        return final_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception scan ports amélioré: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

@celery_app.task(bind=True, name='tasks.adaptive_network_audit')
def adaptive_network_audit(self, target: str, config: Dict = None):
    """Tâche maîtresse qui orchestre un audit adaptatif complet"""
    db = get_db_manager()
    if not db:
        raise Exception("Impossible d'accéder à la base de données")
    
    try:
        from modules.network_discovery import NetworkDiscoveryTool
        from modules.port_scanner import PortScanner

        start_time = time.time()
        logger.info(f"🧠 [Celery] Audit adaptatif démarré sur: {target}")
        
        # Configuration par défaut
        if not config:
            config = {
                'discovery_strategy': 'adaptive',
                'port_strategy': 'adaptive',
                'escalation_mode': 'conservative',
                'max_auto_level': 2
            }
        
        # Mise à jour du statut initial
        db.update_task_status(
            task_id=self.request.id,
            status='running',
            progress=0
        )
        
        audit_phases = []
        
        # Phase 1: Découverte réseau adaptative
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Phase 1/3: Découverte réseau adaptative...',
                'progress': 5,
                'target': target,
                'phase': 'Découverte réseau',
                'audit_type': 'adaptive'
            }
        )
        
        # Options de découverte selon la stratégie
        discovery_options = {
            'timing': config.get('timing', 'T4'),
            'include_top_ports': True,
            'no_ping': config.get('no_ping', False),
            'arp_ping': config.get('arp_ping', False)
        }
        
        discovery_tool = NetworkDiscoveryTool()
        discovery_result = discovery_tool.discover_network(target, discovery_options)
        
        if not discovery_result.get('success'):
            raise Exception(f"Échec découverte réseau: {discovery_result.get('error')}")
        
        hosts_found = discovery_result.get('hosts_found', 0)
        audit_phases.append({
            'phase': 'discovery',
            'success': True,
            'hosts_found': hosts_found,
            'duration': discovery_result.get('duration_seconds', 0)
        })
        
        if hosts_found == 0:
            raise Exception("Aucun hôte découvert - arrêt de l'audit")
        
        # Phase 2: Scan de ports adaptatif
        self.update_state(
            state='PROGRESS',
            meta={
                'status': f'Phase 2/3: Scan ports adaptatif sur {hosts_found} hôte(s)...',
                'progress': 35,
                'target': target,
                'phase': 'Scan ports adaptatif'
            }
        )
        
        # Configuration de l'escalade selon le mode
        escalation_modes = {
            'conservative': {'auto_escalate': True, 'max_auto_level': 2, 'ask_user_above': True},
            'aggressive': {'auto_escalate': True, 'max_auto_level': 3, 'ask_user_above': False},
            'manual': {'auto_escalate': False, 'max_auto_level': 1, 'ask_user_above': True}
        }
        
        escalation_config = escalation_modes.get(
            config.get('escalation_mode', 'conservative'),
            escalation_modes['conservative']
        )
        
        # Options pour le scan de ports
        port_options = {
            'ports': 'docker_quick',  # Point de départ
            'timing': config.get('timing', 'T4'),
            'service_detection': config.get('service_detection', True),
            'os_detection': config.get('os_detection', False),
            'default_scripts': config.get('default_scripts', False)
        }
        
        port_scanner = PortScanner()
        
        # Scanner chaque hôte avec escalade
        all_port_results = []
        total_hosts = len(discovery_result.get('hosts', []))
        
        for i, host in enumerate(discovery_result.get('hosts', [])):
            host_ip = host.get('ip')
            
            # Mise à jour de progression
            progress = 35 + (i * 45 // total_hosts)
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f'Scan adaptatif {host_ip} ({i+1}/{total_hosts})',
                    'progress': progress,
                    'target': target,
                    'phase': 'Scan ports adaptatif',
                    'current_host': host_ip
                }
            )
            
            # Scan avec escalade automatique
            host_result = port_scanner.scan_host_ports(host_ip, port_options, escalation_config)
            all_port_results.append(host_result)
        
        # Analyse des résultats
        successful_scans = len([r for r in all_port_results if r.get('success')])
        total_ports = sum(len(r.get('open_ports', [])) for r in all_port_results)
        total_services = sum(len(r.get('services', [])) for r in all_port_results)
        hosts_with_ports = len([r for r in all_port_results if r.get('open_ports')])
        escalations_used = len([r for r in all_port_results if r.get('escalation_used')])
        
        audit_phases.append({
            'phase': 'port_scan',
            'success': True,
            'hosts_scanned': total_hosts,
            'successful_scans': successful_scans,
            'hosts_with_ports': hosts_with_ports,
            'total_ports': total_ports,
            'total_services': total_services,
            'escalations_used': escalations_used
        })
        
        # Phase 3: Analyse et recommandations
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Phase 3/3: Analyse des résultats et recommandations...',
                'progress': 85,
                'target': target,
                'phase': 'Analyse'
            }
        )
        
        # Générer des recommandations intelligentes
        recommendations = port_scanner.get_scan_recommendations(all_port_results)
        
        # Identifier les prochaines étapes suggérées
        next_steps = []
        if total_services > 0:
            next_steps.append({
                'action': 'service_enumeration',
                'description': f'Énumération détaillée de {total_services} services',
                'priority': 'high'
            })
        
        if hosts_with_ports > 0:
            next_steps.append({
                'action': 'vulnerability_scan', 
                'description': f'Scan vulnérabilités sur {hosts_with_ports} hôtes',
                'priority': 'high'
            })
        
        if escalations_used > 0:
            next_steps.append({
                'action': 'review_escalations',
                'description': f'Réviser {escalations_used} escalades pour optimisation',
                'priority': 'medium'
            })
        
        # Compilation finale de l'audit
        total_duration = time.time() - start_time
        
        adaptive_audit_result = {
            'task_id': self.request.id,
            'audit_type': 'adaptive',
            'target': target,
            'success': True,
            'total_duration': total_duration,
            'phases': audit_phases,
            'discovery_results': discovery_result,
            'port_scan_results': {
                'success': True,
                'results': all_port_results,
                'summary': {
                    'hosts_scanned': total_hosts,
                    'successful_scans': successful_scans,
                    'hosts_with_ports': hosts_with_ports,
                    'total_ports': total_ports,
                    'total_services': total_services,
                    'escalations_used': escalations_used
                }
            },
            'recommendations': recommendations,
            'next_steps': next_steps,
            'config_used': config
        }
        
        # Résumé textuel intelligent
        summary_parts = []
        summary_parts.append(f"Audit adaptatif: {hosts_found} hôtes découverts")
        summary_parts.append(f"{hosts_with_ports} avec ports ouverts")
        summary_parts.append(f"{total_ports} ports, {total_services} services")
        if escalations_used > 0:
            summary_parts.append(f"{escalations_used} escalades utilisées")
        
        summary = ", ".join(summary_parts)
        
        # Finalisation
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Sauvegarde des résultats...',
                'progress': 95,
                'target': target,
                'phase': 'Finalisation'
            }
        )
        
        db.update_task_status(
            task_id=self.request.id,
            status='completed',
            progress=100,
            result_summary=summary
        )
        
        # Sauvegarder le résumé de l'audit adaptatif
        try:
            if hasattr(db, 'save_module_result'):
                db.save_module_result(
                    task_id=self.request.id,
                    module_name='adaptive_audit',
                    result_data=adaptive_audit_result
                )
        except Exception as save_error:
            logger.warning(f"⚠️ Impossible de sauvegarder l'audit adaptatif: {save_error}")
        
        logger.info(f"🧠 [Celery] Audit adaptatif terminé: {summary}")
        return adaptive_audit_result
        
    except Exception as e:
        logger.error(f"💥 [Celery] Exception audit adaptatif: {e}")
        
        db.update_task_status(
            task_id=self.request.id,
            status='failed',
            error_message=str(e)
        )
        raise

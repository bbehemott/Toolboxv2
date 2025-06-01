import subprocess
import xml.etree.ElementTree as ET
import json
import logging
import tempfile
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import time

logger = logging.getLogger(__name__)

class PortScanner:
    """Scanner de ports avancé avec stratégie multi-niveaux et escalade automatique"""
    
    def __init__(self):
        self.nmap_cmd = "nmap"
        self.temp_dir = "/tmp/scans"
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Définition des presets avec métadonnées
        self.presets = {
            'docker_quick': {
                'ports': '-p 21,22,25,53,80,443,3000,3306,5000,5432,5555,6379,8000,8080,8443,8888,9000,9092,9200,27017',
                'description': 'Ports Docker/Dev (20 ports critiques)',
                'estimated_seconds': 60,
                'level': 1,
                'port_count': 20
            },
            'top_100': {
                'ports': '--top-ports 100',
                'description': '100 ports les plus communs',
                'estimated_seconds': 120,
                'level': 1,
                'port_count': 100
            },
            'top_1000': {
                'ports': '--top-ports 1000',
                'description': '1000 ports les plus communs',
                'estimated_seconds': 300,
                'level': 2,
                'port_count': 1000
            },
            'common_extended': {
                'ports': '-p 1-1024,3000-3100,5000-5100,8000-8100,9000-9100,27017,6379,9200',
                'description': 'Ports standard + ranges modernes',
                'estimated_seconds': 600,
                'level': 2,
                'port_count': 1200
            },
            'top_10000': {
                'ports': '--top-ports 10000',
                'description': '10000 ports les plus communs',
                'estimated_seconds': 1200,
                'level': 3,
                'port_count': 10000
            },
            'full_tcp': {
                'ports': '-p-',
                'description': 'TOUS les ports TCP (1-65535)',
                'estimated_seconds': 3600,
                'level': 4,
                'port_count': 65535
            },
            'custom': {
                'ports': '',  # Sera défini dynamiquement
                'description': 'Liste personnalisée',
                'estimated_seconds': 300,
                'level': 2,
                'port_count': 0
            }
        }
        
        # Hiérarchie d'escalade
        self.escalation_hierarchy = [
            'docker_quick',
            'top_1000', 
            'top_10000',
            'full_tcp'
        ]
        
        # Configuration par défaut
        self.default_escalation_config = {
            'auto_escalate': True,
            'max_auto_level': 2,  # Auto jusqu'au niveau 2
            'ask_user_above': True,
            'stop_on_first_success': True
        }
    
    def get_preset_info(self, preset_name: str) -> Dict:
        """Récupère les informations d'un preset"""
        return self.presets.get(preset_name, self.presets['top_1000'])
    
    def estimate_scan_time(self, preset_name: str, host_count: int = 1) -> Dict:
        """Estime le temps de scan"""
        preset = self.get_preset_info(preset_name)
        base_time = preset['estimated_seconds']
        
        # Facteur de multiplication selon le nombre d'hôtes
        if host_count <= 5:
            time_factor = host_count
        elif host_count <= 20:
            time_factor = host_count * 0.8  # Parallélisation
        else:
            time_factor = host_count * 0.6  # Plus de parallélisation
        
        estimated_total = int(base_time * time_factor)
        
        return {
            'preset': preset_name,
            'estimated_seconds': estimated_total,
            'estimated_minutes': round(estimated_total / 60, 1),
            'estimated_human': self._format_duration(estimated_total),
            'host_count': host_count,
            'ports_per_host': preset['port_count']
        }
    
    def _format_duration(self, seconds: int) -> str:
        """Formate une durée en format lisible"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}min {seconds % 60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}min"
    
    def build_nmap_command(self, target: str, options: Dict = None) -> List[str]:
        """Construit la commande Nmap avec toutes les options"""
        if not options:
            options = {}
        
        # Fichier de sortie temporaire
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.temp_dir, f"portscan_{target.replace('/', '_')}_{timestamp}.xml")
        
        # Commande de base
        cmd = [
            self.nmap_cmd,
            "-sS",  # TCP SYN scan
            "-oX", output_file  # Sortie XML
        ]
        
        # Ports à scanner
        preset_name = options.get('ports', 'docker_quick')
        preset = self.get_preset_info(preset_name)
        
        if preset_name == 'custom' and options.get('custom_ports'):
            cmd.extend(["-p", options['custom_ports']])
        else:
            port_option = preset['ports']
            if port_option.startswith('--top-ports'):
                cmd.extend(port_option.split())
            else:
                cmd.extend(port_option.split())
        
        # Timing
        timing = options.get('timing', 'T4')
        cmd.append(f"-{timing}")
        
        # Détection de services
        if options.get('service_detection', True):
            cmd.append("-sV")
            if options.get('version_intensity'):
                cmd.extend(["--version-intensity", str(options['version_intensity'])])
        
        # Détection d'OS
        if options.get('os_detection', False):
            cmd.append("-O")
        
        # Scripts NSE
        if options.get('default_scripts', False):
            cmd.append("-sC")
        elif options.get('custom_scripts'):
            cmd.extend(["--script", options['custom_scripts']])
        
        # Options de performance
        if options.get('max_parallelism'):
            cmd.extend(["--min-parallelism", str(options['max_parallelism'])])
        
        # Timeouts
        if options.get('host_timeout'):
            cmd.extend(["--host-timeout", f"{options['host_timeout']}s"])
        
        # Cible
        cmd.append(target)
        
        logger.info(f"🔍 Commande Nmap construite: {' '.join(cmd)}")
        
        return cmd, output_file
    
    def scan_host_ports(self, target: str, options: Dict = None, escalation_config: Dict = None) -> Dict:
        """Scan de ports avec escalade automatique"""
        if not options:
            options = {}
        
        if not escalation_config:
            escalation_config = self.default_escalation_config.copy()
        
        logger.info(f"🎯 Début scan ports sur {target}")
        
        # Si escalade désactivée, scan simple
        if not escalation_config.get('auto_escalate', False):
            return self._single_port_scan(target, options)
        
        # Scan avec escalade
        return self._escalated_port_scan(target, options, escalation_config)
    
    def _single_port_scan(self, target: str, options: Dict) -> Dict:
        """Effectue un scan simple sans escalade"""
        try:
            start_time = time.time()
            
            # Construction de la commande
            cmd, output_file = self.build_nmap_command(target, options)
            
            # Exécution
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', 1800)  # 30 min par défaut
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur Nmap: {result.stderr}")
                return {
                    'success': False,
                    'error': f"Nmap failed: {result.stderr}",
                    'host': target,
                    'open_ports': [],
                    'services': []
                }
            
            # Parse des résultats
            scan_results = self._parse_nmap_port_xml(output_file, target)
            
            # Nettoyage
            if os.path.exists(output_file):
                os.remove(output_file)
            
            # Enrichissement des résultats
            scan_results.update({
                'scan_duration': time.time() - start_time,
                'command_executed': ' '.join(cmd),
                'preset_used': options.get('ports', 'docker_quick'),
                'escalation_used': False
            })
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Timeout scan ports pour {target}")
            return {
                'success': False,
                'error': 'Timeout during port scan',
                'host': target,
                'open_ports': [],
                'services': []
            }
        except Exception as e:
            logger.error(f"💥 Exception scan ports {target}: {e}")
            return {
                'success': False,
                'error': str(e),
                'host': target,
                'open_ports': [],
                'services': []
            }
    
    def _escalated_port_scan(self, target: str, base_options: Dict, escalation_config: Dict) -> Dict:
        """Effectue un scan avec escalade automatique"""
        max_auto_level = escalation_config.get('max_auto_level', 2)
        ask_user_above = escalation_config.get('ask_user_above', True)
        
        results_history = []
        final_result = None
        
        for level, preset_name in enumerate(self.escalation_hierarchy, 1):
            preset_info = self.get_preset_info(preset_name)
            
            logger.info(f"🔍 Niveau {level}: Scan avec preset '{preset_name}' ({preset_info['description']})")
            
            # Préparer les options pour ce niveau
            level_options = base_options.copy()
            level_options['ports'] = preset_name
            
            # Effectuer le scan
            scan_result = self._single_port_scan(target, level_options)
            
            # Enregistrer dans l'historique
            results_history.append({
                'level': level,
                'preset': preset_name,
                'result': scan_result,
                'ports_found': len(scan_result.get('open_ports', [])),
                'success': scan_result.get('success', False)
            })
            
            # Si succès (ports trouvés), arrêter l'escalade
            if scan_result.get('success') and scan_result.get('open_ports'):
                logger.info(f"✅ Succès niveau {level}: {len(scan_result['open_ports'])} ports trouvés")
                final_result = scan_result
                break
            
            # Si pas de succès, décider de continuer ou non
            if level >= max_auto_level:
                if ask_user_above and level < len(self.escalation_hierarchy):
                    # Dans un vrai environnement, ici on demanderait à l'utilisateur
                    # Pour l'instant, on s'arrête
                    logger.info(f"⚠️ Niveau {level} atteint, arrêt de l'escalade automatique")
                    final_result = scan_result
                    break
                elif not ask_user_above:
                    # Continuer automatiquement
                    continue
                else:
                    final_result = scan_result
                    break
            
            logger.info(f"⚠️ Niveau {level}: Aucun port trouvé, escalade vers niveau {level + 1}")
        
        # Si on arrive ici sans résultat, prendre le dernier
        if not final_result:
            final_result = results_history[-1]['result'] if results_history else {
                'success': False,
                'error': 'Aucun scan effectué',
                'host': target,
                'open_ports': [],
                'services': []
            }
        
        # Enrichir avec l'historique d'escalade
        final_result.update({
            'escalation_used': True,
            'escalation_history': results_history,
            'final_level': len(results_history),
            'total_escalation_time': sum(r['result'].get('scan_duration', 0) for r in results_history)
        })
        
        return final_result
    
    def _parse_nmap_port_xml(self, xml_file: str, target_host: str) -> Dict:
        """Parse un fichier XML Nmap pour extraire les informations de ports - VERSION AMÉLIORÉE"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Trouver l'hôte correspondant
            host_element = None
            for host in root.findall('host'):
                address = host.find('address')
                if address is not None and address.get('addr') == target_host:
                    host_element = host
                    break
            
            if host_element is None:
                return {
                    'success': False,
                    'error': 'Host not found in XML results',
                    'host': target_host,
                    'open_ports': [],
                    'services': []
                }
            
            # Vérifier le statut de l'hôte
            status = host_element.find('status')
            if status is None or status.get('state') != 'up':
                return {
                    'success': False,
                    'error': 'Host is down or unreachable',
                    'host': target_host,
                    'open_ports': [],
                    'services': []
                }
            
            # Parser les ports
            open_ports = []
            services = []
            
            ports_element = host_element.find('ports')
            if ports_element is not None:
                for port in ports_element.findall('port'):
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol', 'tcp')
                    
                    # État du port
                    state = port.find('state')
                    if state is None or state.get('state') != 'open':
                        continue
                    
                    port_info = {
                        'port': port_num,
                        'protocol': protocol,
                        'state': 'open'
                    }
                    
                    # Informations sur le service
                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', 'unknown')
                        service_product = service.get('product', '')
                        service_version = service.get('version', '')
                        service_extrainfo = service.get('extrainfo', '')
                        
                        # Construire la version complète
                        version_parts = []
                        if service_product:
                            version_parts.append(service_product)
                        if service_version:
                            version_parts.append(service_version)
                        if service_extrainfo:
                            version_parts.append(f"({service_extrainfo})")
                        
                        full_version = ' '.join(version_parts) if version_parts else service_name
                        
                        service_info = {
                            'service': service_name,
                            'product': service_product,
                            'version': service_version,
                            'extrainfo': service_extrainfo,
                            'full_version': full_version
                        }
                        
                        port_info['service_info'] = service_info
                        
                        # Ajouter à la liste des services
                        services.append({
                            'port': port_num,
                            'protocol': protocol,
                            'service': service_name,
                            'product': service_product,
                            'version': service_version,
                            'full_version': full_version
                        })
                    
                    open_ports.append(port_info)
            
            # Informations sur l'OS
            os_info = {}
            os_element = host_element.find('os')
            if os_element is not None:
                osmatch = os_element.find('osmatch')
                if osmatch is not None:
                    os_info = {
                        'name': osmatch.get('name', 'Unknown'),
                        'accuracy': osmatch.get('accuracy', '0'),
                        'line': osmatch.get('line', '')
                    }
            
            # Temps de scan
            scan_stats = {}
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    scan_stats = {
                        'elapsed': finished.get('elapsed'),
                        'summary': finished.get('summary'),
                        'exit': finished.get('exit')
                    }
            
            # Résultat final structuré
            result = {
                'success': True,
                'host': target_host,
                'total_open_ports': len(open_ports),
                'open_ports': open_ports,
                'services': services,
                'service_count': len(services),
                'os_info': os_info,
                'scan_stats': scan_stats
            }
            
            logger.info(f"✅ Parsing réussi: {len(open_ports)} ports ouverts, {len(services)} services")
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"❌ Erreur parsing XML: {e}")
            return {
                'success': False,
                'error': f'XML parsing error: {e}',
                'host': target_host,
                'open_ports': [],
                'services': []
            }
        except Exception as e:
            logger.error(f"❌ Erreur inattendue lors du parsing: {e}")
            return {
                'success': False,
                'error': str(e),
                'host': target_host,
                'open_ports': [],
                'services': []
            }
    
    def scan_multiple_hosts(self, hosts: List[str], options: Dict = None, escalation_config: Dict = None) -> List[Dict]:
        """Scan de ports sur plusieurs hôtes"""
        if not options:
            options = {}
        
        if not escalation_config:
            escalation_config = self.default_escalation_config.copy()
        
        logger.info(f"🎯 Début scan ports sur {len(hosts)} hôtes")
        
        results = []
        for i, host in enumerate(hosts):
            logger.info(f"🔍 Scan {i+1}/{len(hosts)}: {host}")
            
            host_result = self.scan_host_ports(host, options, escalation_config)
            results.append(host_result)
        
        logger.info(f"✅ Scan terminé sur {len(hosts)} hôtes")
        
        return results
    
    def get_scan_recommendations(self, results: List[Dict]) -> Dict:
        """Analyse les résultats et fournit des recommandations"""
        total_hosts = len(results)
        successful_scans = len([r for r in results if r.get('success')])
        hosts_with_ports = len([r for r in results if r.get('open_ports')])
        hosts_without_ports = total_hosts - hosts_with_ports
        
        recommendations = {
            'summary': {
                'total_hosts': total_hosts,
                'successful_scans': successful_scans,
                'hosts_with_ports': hosts_with_ports,
                'hosts_without_ports': hosts_without_ports
            },
            'recommendations': []
        }
        
        # Recommandations basées sur les résultats
        if hosts_without_ports > total_hosts * 0.3:
            recommendations['recommendations'].append({
                'type': 'warning',
                'message': f'{hosts_without_ports}/{total_hosts} hôtes sans ports détectés',
                'suggestion': 'Considérez un scan plus approfondi ou vérifiez les firewalls',
                'action': 'rescan_deeper'
            })
        
        if successful_scans < total_hosts:
            failed_scans = total_hosts - successful_scans
            recommendations['recommendations'].append({
                'type': 'error',
                'message': f'{failed_scans} scans échoués',
                'suggestion': 'Vérifiez la connectivité réseau et les timeouts',
                'action': 'check_connectivity'
            })
        
        # Analyse des services trouvés
        all_services = {}
        for result in results:
            for service in result.get('services', []):
                service_name = service.get('service', 'unknown')
                all_services[service_name] = all_services.get(service_name, 0) + 1
        
        if all_services:
            top_services = sorted(all_services.items(), key=lambda x: x[1], reverse=True)[:5]
            recommendations['top_services'] = dict(top_services)
        
        return recommendations

# Fonction utilitaire pour les tests
def test_port_scanner():
    """Test du scanner de ports"""
    scanner = PortScanner()
    
    # Test avec escalade
    options = {
        'service_detection': True,
        'timing': 'T4'
    }
    
    escalation_config = {
        'auto_escalate': True,
        'max_auto_level': 2,
        'ask_user_above': False
    }
    
    result = scanner.scan_host_ports("127.0.0.1", options, escalation_config)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_port_scanner()

# modules/decouverte_reseau.py - Module Découverte Réseau
import logging
import re
from typing import Dict, List, Optional
from core.nmap_wrapper import NmapWrapper

logger = logging.getLogger('toolbox')

class DecouverteReseauModule:
    """
    Module spécialisé pour la découverte et cartographie réseau
    
    Mission: Identifier tous les hôtes actifs sur un réseau
    Outils utilisés: Nmap (discovery), optionnellement Wireshark
    """
    
    def __init__(self):
        self.nmap = NmapWrapper()
        self.name = "Découverte Réseau"
        self.description = "Cartographie complète du réseau - identification des hôtes actifs"
    
    def execute_full_discovery(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Exécute une découverte réseau complète
        
        Args:
            target: Réseau à scanner (IP, CIDR, plage)
            options: Options avancées (timeout, méthodes, etc.)
            
        Returns:
            Dict avec résultats complets de découverte
        """
        try:
            logger.info(f"[Module Découverte] Début scan complet: {target}")
            
            # Validation de la cible
            is_valid, validation_msg = NmapWrapper.validate_target(target)
            if not is_valid:
                return {
                    'success': False,
                    'error': f"Cible invalide: {validation_msg}",
                    'module': self.name
                }
            
            # Configuration par défaut
            default_options = {
                'ping_sweep': True,
                'port_discovery': True,
                'os_detection': True,
                'service_detection': True,
                'aggressive': True
            }

            logger.info(f"[Module Découverte] Mode forcé: COMPLET + AGRESSIF + SERVICES")
            
            if options:
                default_options.update(options)
            
            results = {
                'success': True,
                'module': self.name,
                'target': target,
                'validation_msg': validation_msg,
                'phases': {},
                'summary': {},
                'hosts': [],
                'raw_outputs': []
            }
            
            # PHASE 1: Découverte de base (ping sweep)
            logger.info(f"[Module Découverte] Phase 1: Ping sweep")
            discovery_result = self.nmap.discovery_scan(target)
            
            if discovery_result['success']:
                results['phases']['ping_sweep'] = discovery_result
                results['raw_outputs'].append({
                    'phase': 'ping_sweep',
                    'output': discovery_result.get('raw_output', '')
                })
                
                active_hosts = discovery_result.get('hosts_up', [])
                logger.info(f"[Module Découverte] Phase 1 terminée: {len(active_hosts)} hôtes trouvés")
                

                if default_options['port_discovery'] and active_hosts:
                    logger.info(f"[Module Découverte] Phase 2: Découverte ports sur {len(active_hosts)} hôtes")
    
                    for host in active_hosts[:5]:  # Limiter à 5 hôtes
                        # CORRECTION: Extraire seulement l'IP depuis "dvwa (172.18.0.3)"
                        if '(' in host and ')' in host:
                            # Format: "dvwa (172.18.0.3)" -> extraire "172.18.0.3"
                            ip_match = re.search(r'\(([\d\.]+)\)', host)
                            target_ip = ip_match.group(1) if ip_match else host
                        else:
                            target_ip = host
                            
                        logger.info(f"[Module Découverte] Scan ports sur {target_ip}")
                        host_info = self._discover_host_details(target_ip, default_options)
                        results['hosts'].append(host_info)
                else:
                    logger.warning(f"[Module Découverte] Phase 2 sautée: port_discovery={default_options['port_discovery']}, hosts={len(active_hosts) if active_hosts else 0}")
                
                # Générer le résumé
                results['summary'] = self._generate_discovery_summary(results)
                
                logger.info(f"[Module Découverte] Scan terminé avec succès")
                return results
                
            else:
                return {
                    'success': False,
                    'error': f"Échec ping sweep: {discovery_result.get('error', 'Erreur inconnue')}",
                    'module': self.name,
                    'raw_output': discovery_result.get('raw_output', '')
                }
                
        except Exception as e:
            logger.error(f"[Module Découverte] Erreur: {e}")
            return {
                'success': False,
                'error': f"Erreur module: {str(e)}",
                'module': self.name
            }
    
    def _discover_host_details(self, host: str, options: Dict) -> Dict:
        """Découvre les détails d'un hôte spécifique"""
        try:
            host_info = {
                'ip': host,
                'status': 'up',
                'ports': [],
                'services': [],
                'os': None,
                'scan_success': True
            }
            
            # DEBUG: Ajouter ces logs pour voir ce qui se passe
            logger.info(f"[DEBUG] Options reçues dans _discover_host_details: {options}")
            logger.info(f"[DEBUG] service_detection = {options.get('service_detection', False)}")
            logger.info(f"[DEBUG] aggressive = {options.get('aggressive', False)}")
            
            # Scan rapide des ports les plus courants
            port_result = self.nmap.port_scan(host, "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3389,5000,8080,9000")
            
            if port_result['success']:
                host_info['ports'] = port_result.get('open_ports', [])
                
                # Si option service detection activée
                if options.get('service_detection', False) and host_info['ports']:
                    logger.info(f"[DEBUG] Lancement service enumeration sur {host}")
                    service_result = self.nmap.service_enumeration(host)
                    logger.info(f"[DEBUG] Résultat service enum: {service_result.get('success')}")
                    if service_result['success']:
                        host_info['services'] = service_result.get('services', [])
                        logger.info(f"[DEBUG] Services trouvés: {host_info['services']}")
        
                        host_info['service_raw_output'] = service_result.get('raw_output', '')
                    else:
                        logger.error(f"[DEBUG] Échec service enum: {service_result.get('error')}")
                else:
                    logger.warning(f"[DEBUG] Service detection sautée: service_detection={options.get('service_detection')}, ports={len(host_info.get('ports', []))}")

                if options.get('aggressive', False) and host_info['ports']:
                    logger.info(f"[DEBUG] Mode agressif activé sur {host}")
        
        # 1. Détection de l'OS
                    try:
                       os_result = self.nmap.os_detection(host)
                       if os_result['success']:
                           host_info['os'] = os_result.get('os_info', 'Inconnu')
                           logger.info(f"[DEBUG] OS détecté: {host_info['os']}")
                       else:
                           host_info['os'] = 'Échec détection OS'
                           logger.warning(f"[DEBUG] Échec détection OS: {os_result.get('error')}")
                    except Exception as e:
                        host_info['os'] = f'Erreur OS: {str(e)}'
                        logger.error(f"[DEBUG] Erreur OS detection: {e}")
        
        # 2. Scripts NSE agressifs pour plus d'infos
                    try:
                       aggressive_result = self.nmap.aggressive_scan(host)
                       if aggressive_result['success']:
                           host_info['additional_info'] = aggressive_result.get('extra_info', [])
                           logger.info(f"[DEBUG] Infos agressives trouvées: {len(host_info['additional_info'])}")
                       else:
                           host_info['additional_info'] = []
                           logger.warning(f"[DEBUG] Échec scan agressif: {aggressive_result.get('error')}")
                    except Exception as e:
                        host_info['additional_info'] = [f'Erreur: {str(e)}']
                        logger.error(f"[DEBUG] Erreur aggressive scan: {e}")
        
                    logger.info(f"[DEBUG] Mode agressif terminé sur {host}")
                else:
                    logger.info(f"[DEBUG] Mode agressif sauté: aggressive={options.get('aggressive')}, ports={len(host_info.get('ports', []))}")
    # ✅ FIN DU CODE MODE AGRESSIF ⬆️

            else:
                host_info['scan_success'] = False
                host_info['error'] = port_result.get('error', 'Erreur scan ports')
            
            return host_info
            
        except Exception as e:
            return {
                'ip': host,
                'status': 'error',
                'scan_success': False,
                'error': str(e)
            }


    
    def _generate_discovery_summary(self, results: Dict) -> Dict:
        """Génère un résumé de la découverte"""
        summary = {
            'total_hosts_found': 0,
            'hosts_with_open_ports': 0,
            'total_open_ports': 0,
            'most_common_ports': {},
            'potential_servers': [],
            'network_map': []
        }
        
        # Compter les hôtes
        if 'ping_sweep' in results['phases']:
            summary['total_hosts_found'] = results['phases']['ping_sweep'].get('total_found', 0)
        
        # Analyser les hôtes détaillés
        port_counter = {}
        for host in results.get('hosts', []):
            if host.get('scan_success', False):
                open_ports = host.get('ports', [])
                if open_ports:
                    summary['hosts_with_open_ports'] += 1
                    summary['total_open_ports'] += len(open_ports)
                    
                    # Compter la fréquence des ports
                    for port_info in open_ports:
                        port = port_info.get('port', 'unknown')
                        port_counter[port] = port_counter.get(port, 0) + 1
                    
                    # Identifier les serveurs potentiels
                    if any(p.get('port', '').startswith(('80/', '443/', '8080/')) for p in open_ports):
                        summary['potential_servers'].append({
                            'ip': host['ip'],
                            'type': 'Web Server',
                            'ports': [p['port'] for p in open_ports if p.get('port', '').startswith(('80/', '443/', '8080/'))]
                        })
                    
                    if any(p.get('port', '').startswith(('22/', '3389/')) for p in open_ports):
                        summary['potential_servers'].append({
                            'ip': host['ip'],
                            'type': 'Remote Access',
                            'ports': [p['port'] for p in open_ports if p.get('port', '').startswith(('22/', '3389/'))]
                        })
        
        # Top 5 des ports les plus fréquents
        sorted_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)
        summary['most_common_ports'] = dict(sorted_ports[:5])
        
        return summary
    
    def quick_discovery(self, target: str) -> Dict:
        """
        Découverte rapide - ping sweep seulement
        
        Args:
            target: Réseau à scanner
            
        Returns:
            Dict avec hôtes actifs trouvés
        """
        try:
            logger.info(f"[Module Découverte] Quick discovery: {target}")
            
            # Validation
            is_valid, validation_msg = NmapWrapper.validate_target(target)
            if not is_valid:
                return {
                    'success': False,
                    'error': f"Cible invalide: {validation_msg}",
                    'module': self.name
                }
            
            # Ping sweep seulement
            result = self.nmap.discovery_scan(target)
            
            if result['success']:
                return {
                    'success': True,
                    'module': self.name,
                    'target': target,
                    'validation_msg': validation_msg,
                    'hosts_found': result.get('hosts_up', []),
                    'total_found': result.get('total_found', 0),
                    'scan_type': 'quick',
                    'raw_output': result.get('raw_output', '')
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Erreur ping sweep'),
                    'module': self.name,
                    'raw_output': result.get('raw_output', '')
                }
                
        except Exception as e:
            logger.error(f"[Module Découverte] Erreur quick discovery: {e}")
            return {
                'success': False,
                'error': f"Erreur module: {str(e)}",
                'module': self.name
            }
    
    def get_module_info(self) -> Dict:
        """Retourne les informations du module"""
        return {
            'name': self.name,
            'description': self.description,
            'capabilities': [
                'Ping sweep réseau',
                'Découverte hôtes actifs',
                'Scan ports communs',
                'Identification serveurs',
                'Cartographie réseau'
            ],
            'tools_used': ['Nmap'],
            'typical_duration': '1-5 minutes selon taille réseau'
        }

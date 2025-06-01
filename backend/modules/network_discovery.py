import subprocess
import json
import xml.etree.ElementTree as ET
import logging
import ipaddress
from typing import Dict, List, Optional, Tuple
import tempfile
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkDiscoveryTool:
    """Wrapper pour la découverte réseau avec Nmap uniquement"""
    
    def __init__(self):
        self.nmap_cmd = "nmap"
        self.temp_dir = "/tmp/scans"
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Valide une cible (IP, CIDR, ou range)"""
        try:
            # Test CIDR
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return True, "CIDR valide"
            
            # Test IP simple
            if '-' not in target:
                ipaddress.ip_address(target)
                return True, "IP valide"
            
            # Test range (ex: 192.168.1.1-254)
            if '-' in target and '.' in target:
                base_ip, range_part = target.rsplit('.', 1)
                if '-' in range_part:
                    start, end = range_part.split('-')
                    if start.isdigit() and end.isdigit():
                        return True, "Range IP valide"
            
            return False, "Format de cible invalide"
            
        except Exception as e:
            return False, f"Erreur validation: {str(e)}"
    
    def host_discovery_nmap(self, target: str, options: Dict = None) -> Dict:
        """Découverte d'hôtes avec Nmap - VERSION AMÉLIORÉE"""
        try:
            output_file = os.path.join(self.temp_dir, f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
            
            # Commande Nmap pour découverte d'hôtes
            cmd = [
                self.nmap_cmd,
                "-sn",  # Ping scan (pas de scan de ports par défaut)
                "-T4",  # Timing agressif
                "-oX", output_file,  # Sortie XML
                target
            ]
            
            # Options supplémentaires
            if options:
                timing = options.get('timing', 'T4')
                if timing != 'T4':
                    cmd[2] = f"-{timing}"  # Remplacer le timing par défaut
                
                if options.get('no_ping', False):
                    cmd.append("-Pn")
                if options.get('arp_ping', False):
                    cmd.append("-PR")
                if options.get('udp_ping', False):
                    cmd.append("-PU")
                
                # NOUVELLE OPTION: Inclure un scan de ports léger si demandé
                if options.get('include_top_ports', False):
                    cmd.remove("-sn")  # Retirer le ping-only
                    cmd.extend(["-sS", "--top-ports", "100"])  # Ajouter scan des top 100 ports
            
            logger.info(f"🔍 Lancement Nmap discovery: {' '.join(cmd)}")
            
            # Exécution
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur Nmap: {result.stderr}")
                return {
                    "success": False,
                    "error": f"Nmap failed: {result.stderr}",
                    "hosts": []
                }
            
            # Parse du fichier XML
            hosts = self._parse_nmap_xml(output_file)
            
            # Nettoyage
            if os.path.exists(output_file):
                os.remove(output_file)
            
            return {
                "success": True,
                "tool": "nmap",
                "target": target,
                "hosts_found": len(hosts),
                "hosts": hosts,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            logger.error("⏰ Timeout Nmap discovery")
            return {
                "success": False,
                "error": "Timeout during Nmap discovery",
                "hosts": []
            }
        except Exception as e:
            logger.error(f"💥 Exception Nmap discovery: {e}")
            return {
                "success": False,
                "error": str(e),
                "hosts": []
            }
    
    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse un fichier XML Nmap pour extraire les hôtes - VERSION AMÉLIORÉE"""
        hosts = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                # Vérifier si l'hôte est up
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Récupérer l'IP
                address = host.find('address')
                if address is None:
                    continue
                
                ip = address.get('addr')
                
                # Informations de base de l'hôte
                host_info = {
                    "ip": ip,
                    "status": "up",
                    "scan_success": True
                }
                
                # Hostname si disponible
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        host_info["hostname"] = hostname_elem.get('name')
                
                # OS detection si disponible
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host_info["os"] = osmatch.get('name')
                        host_info["os_accuracy"] = osmatch.get('accuracy')
                
                # NOUVEAU: Ports si scan avec --top-ports
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    host_ports = []
                    host_services = []
                    
                    for port in ports_elem.findall('port'):
                        port_num = int(port.get('portid'))
                        protocol = port.get('protocol')
                        
                        # État du port
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_info = {
                                "port": port_num,
                                "protocol": protocol,
                                "state": "open"
                            }
                            
                            # Service détecté
                            service = port.find('service')
                            if service is not None:
                                service_name = service.get('name', 'unknown')
                                service_product = service.get('product', '')
                                service_version = service.get('version', '')
                                
                                # Construire la version complète
                                version_parts = []
                                if service_product:
                                    version_parts.append(service_product)
                                if service_version:
                                    version_parts.append(service_version)
                                
                                full_version = ' '.join(version_parts) if version_parts else service_name
                                
                                service_info = {
                                    "port": port_num,
                                    "service": service_name,
                                    "version": full_version
                                }
                                host_services.append(service_info)
                            
                            host_ports.append(port_info)
                    
                    if host_ports:
                        host_info["ports"] = host_ports
                    if host_services:
                        host_info["services"] = host_services
                
                # Informations supplémentaires pour enrichissement
                host_info["additional_info"] = []
                
                # Détecter les types de serveurs potentiels
                if "ports" in host_info:
                    server_types = []
                    for port_info in host_info["ports"]:
                        port_num = port_info["port"]
                        if port_num == 80:
                            server_types.append("Web Server (HTTP)")
                        elif port_num == 443:
                            server_types.append("Web Server (HTTPS)")
                        elif port_num == 22:
                            server_types.append("SSH Server")
                        elif port_num == 21:
                            server_types.append("FTP Server")
                        elif port_num == 25:
                            server_types.append("SMTP Server")
                    
                    if server_types:
                        host_info["additional_info"].extend(server_types)
                
                hosts.append(host_info)
                
        except Exception as e:
            logger.error(f"❌ Erreur parsing XML Nmap: {e}")
        
        return hosts
    
    def discover_network(self, target: str, options: Dict = None) -> Dict:
        """Point d'entrée principal pour la découverte réseau (Nmap uniquement)"""
        
        # Validation de la cible
        is_valid, validation_msg = self.validate_target(target)
        if not is_valid:
            return {
                "success": False,
                "error": validation_msg,
                "hosts": []
            }
        
        logger.info(f"🌐 Début découverte réseau - Cible: {target}")
        
        start_time = datetime.now()
        
        # Découverte avec Nmap uniquement
        result = self.host_discovery_nmap(target, options)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Enrichir le résultat avec métadonnées
        result.update({
            "scan_start": start_time.isoformat(),
            "scan_end": end_time.isoformat(),
            "duration_seconds": duration,
            "method": "nmap",
            "validation": validation_msg
        })
        
        # NOUVEAU: Générer des statistiques avancées
        if result.get("success") and result.get("hosts"):
            hosts = result["hosts"]
            
            # Statistiques générales
            hosts_with_ports = len([h for h in hosts if h.get("ports")])
            total_ports = sum(len(h.get("ports", [])) for h in hosts)
            total_services = sum(len(h.get("services", [])) for h in hosts)
            
            # Ports les plus fréquents
            port_count = {}
            for host in hosts:
                for port in host.get("ports", []):
                    port_num = port["port"]
                    port_count[port_num] = port_count.get(port_num, 0) + 1
            
            # Top 5 des ports
            top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Serveurs potentiels
            potential_servers = []
            server_indicators = {
                80: 'Web Server',
                443: 'HTTPS Server', 
                22: 'SSH Server',
                21: 'FTP Server',
                25: 'SMTP Server',
                53: 'DNS Server',
                3389: 'RDP Server',
                445: 'SMB Server',
                3306: 'MySQL Server',
                5432: 'PostgreSQL Server',
                6379: 'Redis Server',
                27017: 'MongoDB Server',
                9200: 'Elasticsearch',
                5000: 'Flask/Dev Server',
                8080: 'Alt HTTP Server'
            }
            
            for host in hosts:
                if host.get("ports"):
                    server_types = []
                    host_ports = [p["port"] for p in host["ports"]]
                    
                    for port in host_ports:
                        if port in server_indicators:
                            server_types.append(server_indicators[port])
                    
                    if server_types:
                        potential_servers.append({
                            'ip': host['ip'],
                            'type': ', '.join(server_types),
                            'ports': host_ports
                        })
            
            # Ajouter les statistiques au résultat
            result["summary"] = {
                "total_hosts_found": len(hosts),
                "hosts_with_open_ports": hosts_with_ports,
                "total_open_ports": total_ports,
                "total_services": total_services,
                "most_common_ports": dict(top_ports),
                "potential_servers": potential_servers
            }
        
        logger.info(f"✅ Découverte terminée - {result.get('hosts_found', 0)} hôtes trouvés en {duration:.2f}s")
        
        return result

# Fonction utilitaire pour les tests
def test_discovery():
    """Test de la découverte réseau"""
    tool = NetworkDiscoveryTool()
    
    # Test avec une cible locale
    result = tool.discover_network("127.0.0.1", {"include_top_ports": True})
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_discovery()

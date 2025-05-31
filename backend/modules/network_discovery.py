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
    """Wrapper pour la découverte réseau avec Nmap et Masscan"""
    
    def __init__(self):
        self.nmap_cmd = "nmap"
        self.masscan_cmd = "masscan"
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
        """Découverte d'hôtes avec Nmap (ping sweep)"""
        try:
            output_file = os.path.join(self.temp_dir, f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
            
            # Commande Nmap pour découverte d'hôtes
            cmd = [
                self.nmap_cmd,
                "-sn",  # Ping scan (pas de scan de ports)
                "-T4",  # Timing agressif
                "-oX", output_file,  # Sortie XML
                target
            ]
            
            # Options supplémentaires
            if options:
                if options.get('no_ping', False):
                    cmd.append("-Pn")
                if options.get('arp_ping', False):
                    cmd.append("-PR")
                if options.get('udp_ping', False):
                    cmd.append("-PU")
            
            logger.info(f"🔍 Lancement Nmap discovery: {' '.join(cmd)}")
            
            # Exécution
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
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
    
    def host_discovery_masscan(self, target: str, options: Dict = None) -> Dict:
        """Découverte d'hôtes avec Masscan (scan de ports rapide)"""
        try:
            output_file = os.path.join(self.temp_dir, f"masscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            
            # Ports communs pour la découverte
            common_ports = "80,443,22,21,23,25,53,110,139,445,993,995,1723,3389,5900,8080"
            if options and options.get('ports'):
                common_ports = options['ports']
            
            # Commande Masscan
            cmd = [
                self.masscan_cmd,
                target,
                "-p", common_ports,
                "--rate", str(options.get('rate', '1000') if options else '1000'),
                "-oJ", output_file  # Sortie JSON
            ]
            
            logger.info(f"🚀 Lancement Masscan discovery: {' '.join(cmd)}")
            
            # Exécution
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur Masscan: {result.stderr}")
                return {
                    "success": False,
                    "error": f"Masscan failed: {result.stderr}",
                    "hosts": []
                }
            
            # Parse du fichier JSON
            hosts = self._parse_masscan_json(output_file)
            
            # Nettoyage
            if os.path.exists(output_file):
                os.remove(output_file)
            
            return {
                "success": True,
                "tool": "masscan",
                "target": target,
                "hosts_found": len(hosts),
                "hosts": hosts,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            logger.error("⏰ Timeout Masscan discovery")
            return {
                "success": False,
                "error": "Timeout during Masscan discovery",
                "hosts": []
            }
        except Exception as e:
            logger.error(f"💥 Exception Masscan discovery: {e}")
            return {
                "success": False,
                "error": str(e),
                "hosts": []
            }
    
    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse un fichier XML Nmap pour extraire les hôtes"""
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
                
                # Informations supplémentaires
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
                
                hosts.append(host_info)
                
        except Exception as e:
            logger.error(f"❌ Erreur parsing XML Nmap: {e}")
        
        return hosts
    
    def _parse_masscan_json(self, json_file: str) -> List[Dict]:
        """Parse un fichier JSON Masscan pour extraire les hôtes"""
        hosts = {}
        
        try:
            with open(json_file, 'r') as f:
                content = f.read().strip()
                
                # Masscan JSON peut contenir plusieurs objets JSON sur des lignes séparées
                lines = content.split('\n')
                
                for line in lines:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            
                            if 'ip' in data and 'ports' in data:
                                ip = data['ip']
                                port_info = data['ports'][0] if data['ports'] else {}
                                
                                if ip not in hosts:
                                    hosts[ip] = {
                                        "ip": ip,
                                        "status": "up",
                                        "scan_success": True,
                                        "ports": []
                                    }
                                
                                if port_info and 'port' in port_info:
                                    hosts[ip]["ports"].append({
                                        "port": port_info['port'],
                                        "status": port_info.get('status', 'open'),
                                        "protocol": port_info.get('proto', 'tcp')
                                    })
                        except json.JSONDecodeError:
                            continue
                            
        except Exception as e:
            logger.error(f"❌ Erreur parsing JSON Masscan: {e}")
        
        return list(hosts.values())
    
    def discover_network(self, target: str, method: str = "nmap", options: Dict = None) -> Dict:
        """Point d'entrée principal pour la découverte réseau"""
        
        # Validation de la cible
        is_valid, validation_msg = self.validate_target(target)
        if not is_valid:
            return {
                "success": False,
                "error": validation_msg,
                "hosts": []
            }
        
        logger.info(f"🌐 Début découverte réseau - Cible: {target}, Méthode: {method}")
        
        start_time = datetime.now()
        
        # Choix de la méthode
        if method.lower() == "masscan":
            result = self.host_discovery_masscan(target, options)
        else:  # nmap par défaut
            result = self.host_discovery_nmap(target, options)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Enrichir le résultat
        result.update({
            "scan_start": start_time.isoformat(),
            "scan_end": end_time.isoformat(),
            "duration_seconds": duration,
            "method": method,
            "validation": validation_msg
        })
        
        logger.info(f"✅ Découverte terminée - {result.get('hosts_found', 0)} hôtes trouvés en {duration:.2f}s")
        
        return result

# Fonction utilitaire pour les tests
def test_discovery():
    """Test de la découverte réseau"""
    tool = NetworkDiscoveryTool()
    
    # Test avec une cible locale
    result = tool.discover_network("127.0.0.1", "nmap")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_discovery()

import subprocess
import json
import xml.etree.ElementTree as ET
import logging
import tempfile
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class PortScanner:
    """Wrapper pour le scan de ports détaillé avec Nmap"""
    
    def __init__(self):
        self.nmap_cmd = "nmap"
        self.temp_dir = "/tmp/scans"
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Ports par défaut à scanner
        self.default_ports = {
            'top_100': 'nmap --top-ports 100',
            'top_1000': 'nmap --top-ports 1000',
            'common': '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
            'all': '1-65535'
        }
    
    def scan_host_ports(self, host: str, options: Dict = None) -> Dict:
        """Scan les ports d'un hôte spécifique"""
        try:
            if not options:
                options = {}
            
            output_file = os.path.join(self.temp_dir, f"portscan_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
            
            # Configuration du scan
            ports = options.get('ports', 'top_1000')
            timing = options.get('timing', 'T4')
            service_detection = options.get('service_detection', True)
            os_detection = options.get('os_detection', False)
            
            # Construction de la commande Nmap
            cmd = [self.nmap_cmd]
            
            # Scan TCP par défaut
            cmd.extend(["-sS"])  # SYN scan
            
            # Timing
            cmd.extend([f"-{timing}"])
            
            # Ports à scanner
            if ports in self.default_ports:
                if ports == 'top_100':
                    cmd.extend(["--top-ports", "100"])
                elif ports == 'top_1000':
                    cmd.extend(["--top-ports", "1000"])
                elif ports == 'all':
                    cmd.extend(["-p", "1-65535"])
                else:
                    cmd.extend(["-p", self.default_ports[ports]])
            else:
                # Ports personnalisés
                cmd.extend(["-p", str(ports)])
            
            # Détection de services
            if service_detection:
                cmd.extend(["-sV"])
            
            # Détection d'OS
            if os_detection:
                cmd.extend(["-O"])
            
            # Scripts NSE de base
            if options.get('default_scripts', False):
                cmd.extend(["-sC"])
            
            # Sortie XML
            cmd.extend(["-oX", output_file])
            
            # Cible
            cmd.append(host)
            
            logger.info(f"🔍 Lancement scan ports: {' '.join(cmd)}")
            
            # Exécution
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', 600)  # 10 minutes par défaut
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur Nmap ports: {result.stderr}")
                return {
                    "success": False,
                    "host": host,
                    "error": f"Nmap failed: {result.stderr}",
                    "open_ports": []
                }
            
            # Parse du fichier XML
            scan_result = self._parse_nmap_port_xml(output_file, host)
            
            # Nettoyage
            if os.path.exists(output_file):
                os.remove(output_file)
            
            # Enrichir le résultat
            scan_result.update({
                "command": ' '.join(cmd),
                "scan_options": options
            })
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Timeout scan ports pour {host}")
            return {
                "success": False,
                "host": host,
                "error": "Timeout during port scan",
                "open_ports": []
            }
        except Exception as e:
            logger.error(f"💥 Exception scan ports {host}: {e}")
            return {
                "success": False,
                "host": host,
                "error": str(e),
                "open_ports": []
            }
    
    def scan_multiple_hosts(self, hosts: List[str], options: Dict = None) -> List[Dict]:
        """Scan les ports de plusieurs hôtes"""
        results = []
        
        logger.info(f"🎯 Scan de ports sur {len(hosts)} hôte(s)")
        
        for i, host in enumerate(hosts):
            logger.info(f"📡 Scan {i+1}/{len(hosts)}: {host}")
            result = self.scan_host_ports(host, options)
            results.append(result)
        
        return results
    
    def _parse_nmap_port_xml(self, xml_file: str, target_host: str) -> Dict:
        """Parse un fichier XML Nmap pour extraire les ports et services"""
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Initialiser le résultat
            result = {
                "success": True,
                "host": target_host,
                "open_ports": [],
                "services": [],
                "os": None,
                "hostname": None,
                "scan_time": datetime.now().isoformat()
            }
            
            # Trouver l'hôte dans le XML
            host_elem = None
            for host in root.findall('host'):
                address = host.find('address')
                if address is not None and address.get('addr') == target_host:
                    host_elem = host
                    break
            
            if host_elem is None:
                return {
                    "success": False,
                    "host": target_host,
                    "error": "Host not found in scan results",
                    "open_ports": []
                }
            
            # Vérifier le statut de l'hôte
            status = host_elem.find('status')
            if status is None or status.get('state') != 'up':
                return {
                    "success": False,
                    "host": target_host,
                    "error": "Host is down",
                    "open_ports": []
                }
            
            # Récupérer les hostnames
            hostnames = host_elem.find('hostnames')
            if hostnames is not None:
                hostname_elem = hostnames.find('hostname')
                if hostname_elem is not None:
                    result["hostname"] = hostname_elem.get('name')
            
            # Récupérer les ports
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_num = port.get('portid')
                    protocol = port.get('protocol')
                    
                    # État du port
                    state = port.find('state')
                    if state is None:
                        continue
                    
                    port_state = state.get('state')
                    
                    if port_state == 'open':
                        port_info = {
                            "port": int(port_num),
                            "protocol": protocol,
                            "state": port_state
                        }
                        
                        # Service détecté
                        service = port.find('service')
                        if service is not None:
                            service_info = {
                                "port": int(port_num),
                                "protocol": protocol,
                                "service": service.get('name', 'unknown'),
                                "product": service.get('product', ''),
                                "version": service.get('version', ''),
                                "extrainfo": service.get('extrainfo', ''),
                                "confidence": service.get('conf', ''),
                                "method": service.get('method', '')
                            }
                            
                            # Construire la version complète
                            version_parts = []
                            if service_info['product']:
                                version_parts.append(service_info['product'])
                            if service_info['version']:
                                version_parts.append(service_info['version'])
                            if service_info['extrainfo']:
                                version_parts.append(f"({service_info['extrainfo']})")
                            
                            service_info['full_version'] = ' '.join(version_parts)
                            port_info['service_info'] = service_info
                            result["services"].append(service_info)
                        
                        result["open_ports"].append(port_info)
            
            # Récupérer les informations OS
            os_elem = host_elem.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    result["os"] = {
                        "name": osmatch.get('name'),
                        "accuracy": osmatch.get('accuracy'),
                        "line": osmatch.get('line')
                    }
            
            # Scripts NSE
            hostscript = host_elem.find('hostscript')
            if hostscript is not None:
                scripts = []
                for script in hostscript.findall('script'):
                    scripts.append({
                        "id": script.get('id'),
                        "output": script.get('output', '').strip()
                    })
                result["host_scripts"] = scripts
            
            # Statistiques
            result["total_open_ports"] = len(result["open_ports"])
            result["total_services"] = len(result["services"])
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur parsing XML ports: {e}")
            return {
                "success": False,
                "host": target_host,
                "error": f"XML parsing failed: {str(e)}",
                "open_ports": []
            }
    
    def quick_port_check(self, host: str, ports: List[int]) -> Dict:
        """Vérification rapide de ports spécifiques"""
        try:
            ports_str = ','.join(map(str, ports))
            
            cmd = [
                self.nmap_cmd,
                "-p", ports_str,
                "-T4",
                "--open",  # Seulement les ports ouverts
                host
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute max
            )
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "host": host,
                    "error": result.stderr,
                    "open_ports": []
                }
            
            # Parse simple de la sortie
            open_ports = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    try:
                        port_num = int(line.split('/')[0])
                        open_ports.append(port_num)
                    except ValueError:
                        continue
            
            return {
                "success": True,
                "host": host,
                "open_ports": open_ports,
                "checked_ports": ports
            }
            
        except Exception as e:
            return {
                "success": False,
                "host": host,
                "error": str(e),
                "open_ports": []
            }

# Fonction utilitaire pour les tests
def test_port_scanner():
    """Test du scanner de ports"""
    scanner = PortScanner()
    
    # Test scan rapide
    result = scanner.scan_host_ports("127.0.0.1", {
        'ports': 'common',
        'service_detection': True,
        'timing': 'T4'
    })
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    test_port_scanner()

# core/nmap_wrapper.py - Wrapper intelligent pour Nmap
import subprocess
import json
import re
import ipaddress
import socket
import logging
from typing import Dict, List, Optional, Union

logger = logging.getLogger('toolbox')

class NmapWrapper:
    """Wrapper intelligent pour Nmap avec parsing automatique des résultats"""
    
    def __init__(self):
        self.timeout = 300  # 5 minutes par défaut
        
    def discovery_scan(self, target: str) -> Dict:
        """
        Découverte réseau - trouve les hôtes actifs
        
        Args:
            target: IP, plage CIDR ou hostname
            
        Returns:
            Dict avec hosts_up, hosts_down, scan_info
        """
        try:
            logger.info(f"Nmap discovery scan: {target}")
            
            # Commande Nmap pour découverte
            cmd = ['nmap', '-sn', '-PR', target]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'raw_output': result.stdout
                }
            
            # Parser les résultats
            parsed = self._parse_discovery_output(result.stdout)
            parsed['success'] = True
            parsed['raw_output'] = result.stdout
            
            logger.info(f"Discovery terminé: {len(parsed.get('hosts_up', []))} hôtes trouvés")
            return parsed
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - scan trop long',
                'hosts_up': [],
                'hosts_down': []
            }
        except Exception as e:
            logger.error(f"Erreur discovery scan: {e}")
            return {
                'success': False,
                'error': str(e),
                'hosts_up': [],
                'hosts_down': []
            }
    
    def port_scan(self, target: str, ports: str = "1-1000") -> Dict:
        """
        Scan de ports sur une cible
        
        Args:
            target: IP ou hostname
            ports: Ports à scanner (ex: "80,443" ou "1-1000")
            
        Returns:
            Dict avec open_ports, closed_ports, filtered_ports
        """
        try:
            logger.info(f"Nmap port scan: {target}:{ports}")
            
            cmd = ['nmap', '-p', ports, target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'raw_output': result.stdout
                }
            
            # Parser les résultats
            parsed = self._parse_port_scan_output(result.stdout)
            parsed['success'] = True
            parsed['raw_output'] = result.stdout
            parsed['target'] = target
            
            logger.info(f"Port scan terminé: {len(parsed.get('open_ports', []))} ports ouverts")
            return parsed
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - scan trop long',
                'open_ports': [],
                'closed_ports': []
            }
        except Exception as e:
            logger.error(f"Erreur port scan: {e}")
            return {
                'success': False,
                'error': str(e),
                'open_ports': [],
                'closed_ports': []
            }
    
    def service_enumeration(self, target: str, ports: Optional[str] = None) -> Dict:
        """
        Énumération des services (-sV)
        
        Args:
            target: IP ou hostname
            ports: Ports spécifiques ou None pour auto-détection
            
        Returns:
            Dict avec services détectés
        """
        try:
            logger.info(f"Nmap service enum: {target}")
            
            if ports:
                cmd = ['nmap', '-sV', '-p', ports, target]
            else:
                cmd = ['nmap', '-sV', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'raw_output': result.stdout
                }
            
            # Parser les résultats
            parsed = self._parse_service_output(result.stdout)
            parsed['success'] = True
            parsed['raw_output'] = result.stdout
            parsed['target'] = target
            
            logger.info(f"Service enum terminé: {len(parsed.get('services', []))} services")
            return parsed
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - scan trop long',
                'services': []
            }
        except Exception as e:
            logger.error(f"Erreur service enum: {e}")
            return {
                'success': False,
                'error': str(e),
                'services': []
            }
    
    def vulnerability_scan(self, target: str, scripts: Optional[str] = None) -> Dict:
        """
        Scan de vulnérabilités avec scripts NSE
        
        Args:
            target: IP ou hostname
            scripts: Scripts spécifiques ou None pour 'vuln'
            
        Returns:
            Dict avec vulnérabilités trouvées
        """
        try:
            logger.info(f"Nmap vuln scan: {target}")
            
            script_arg = scripts or 'vuln'
            cmd = ['nmap', '-sV', '--script', script_arg, target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2  # Plus long pour vulns
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'raw_output': result.stdout
                }
            
            # Parser les résultats
            parsed = self._parse_vulnerability_output(result.stdout)
            parsed['success'] = True
            parsed['raw_output'] = result.stdout
            parsed['target'] = target
            
            vuln_count = len(parsed.get('vulnerabilities', []))
            logger.info(f"Vuln scan terminé: {vuln_count} vulnérabilités")
            return parsed
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - scan trop long',
                'vulnerabilities': []
            }
        except Exception as e:
            logger.error(f"Erreur vuln scan: {e}")
            return {
                'success': False,
                'error': str(e),
                'vulnerabilities': []
            }
    
    def os_detection(self, target: str) -> Dict:
        """Détection de l'OS avec Nmap -O"""
        try:
            logger.info(f"Nmap OS detection: {target}")
            cmd = ['nmap', '-O', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        
            if result.returncode == 0:
                # Parser la sortie pour extraire l'OS
                os_info = self._parse_os_detection(result.stdout)
                return {
                    'success': True,
                    'os_info': os_info,
                    'raw_output': result.stdout
                }
            return {'success': False, 'error': result.stderr}
        except Exception as e:
            logger.error(f"Erreur OS detection: {e}")
            return {'success': False, 'error': str(e)}

    def aggressive_scan(self, target: str) -> Dict:
        """Scan avec timing agressif et scripts NSE"""
        try:
            logger.info(f"Nmap aggressive scan: {target}")
            cmd = ['nmap', '-T4', '-A', target]  # -A = agressif (OS, version, scripts, traceroute)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout * 2)
        
            if result.returncode == 0:
                extra_info = self._parse_aggressive_output(result.stdout)
                return {
                    'success': True,
                    'extra_info': extra_info,
                    'raw_output': result.stdout
                }
            return {'success': False, 'error': result.stderr}
        except Exception as e:
            logger.error(f"Erreur aggressive scan: {e}")
            return {'success': False, 'error': str(e)}

    def _parse_os_detection(self, output: str) -> str:
        """Parse la sortie de détection d'OS"""
        lines = output.split('\n')
        for line in lines:
            if 'OS details:' in line:
                return line.replace('OS details:', '').strip()
            elif 'Running:' in line:
                return line.replace('Running:', '').strip()
            elif 'OS:' in line and 'OS details:' not in line:
                return line.replace('OS:', '').strip()
        return 'OS non détecté'

    def _parse_aggressive_output(self, output: str) -> List[str]:
        """Parse la sortie du scan agressif pour extraire infos supplémentaires"""
        extra_info = []
        lines = output.split('\n')
    
        for line in lines:
            line = line.strip()
        
            # ✅ CORRECTION : Chercher les lignes avec | ou |_
            if (line.startswith('|_') or line.startswith('|')) and len(line) > 3:
                # Nettoyer et ajouter les résultats de scripts
                script_result = line.strip('|_| ').strip()
                if script_result and not script_result.startswith('_'):
                    extra_info.append(script_result)
        
            # ✅ AJOUT : Capturer aussi les infos OS et autres détails utiles
            elif 'Running:' in line:
                os_info = line.replace('Running:', '').strip()
                if os_info:
                    extra_info.append(f"OS Running: {os_info}")
                
            elif 'OS details:' in line:
                os_details = line.replace('OS details:', '').strip()
                if os_details:
                    extra_info.append(f"OS Details: {os_details}")
        
            elif 'Network Distance:' in line:
                network = line.strip()
                if network:
                    extra_info.append(network)
    
        return extra_info[:10]  # Limiter à 10 infos


    def _parse_discovery_output(self, output: str) -> Dict:
        """Parse la sortie du discovery scan"""
        hosts_up = []
        hosts_down = []
        
        lines = output.split('\n')
        for line in lines:
            # Chercher les hôtes actifs
            if 'Nmap scan report for' in line:
                # Extraire l'IP/hostname
                match = re.search(r'Nmap scan report for (.+)', line)
                if match:
                    host = match.group(1).strip()
                    hosts_up.append(host)
            
            # Statistiques finales
            elif 'hosts up' in line:
                stats_match = re.search(r'(\d+) hosts up', line)
                if stats_match:
                    total_up = int(stats_match.group(1))
        
        return {
            'hosts_up': hosts_up,
            'hosts_down': hosts_down,
            'total_found': len(hosts_up)
        }
    
    def _parse_port_scan_output(self, output: str) -> Dict:
        """Parse la sortie du port scan"""
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        lines = output.split('\n')
        for line in lines:
            # Format: PORT     STATE SERVICE
            if '/' in line and ('open' in line or 'closed' in line or 'filtered' in line):
                parts = line.split()
                if len(parts) >= 2:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    port_info = {
                        'port': port,
                        'state': state,
                        'service': service
                    }
                    
                    if state == 'open':
                        open_ports.append(port_info)
                    elif state == 'closed':
                        closed_ports.append(port_info)
                    elif state == 'filtered':
                        filtered_ports.append(port_info)
        
        return {
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'filtered_ports': filtered_ports,
            'total_scanned': len(open_ports) + len(closed_ports) + len(filtered_ports)
        }
    
    def _parse_service_output(self, output: str) -> Dict:
        """Parse la sortie de l'énumération de services"""
        services = []
        
        lines = output.split('\n')
        for line in lines:
            # Format avec version: PORT     STATE SERVICE VERSION
            if '/' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    
                    service_info = {
                        'port': port,
                        'service': service,
                        'version': version,
                        'state': state
                    }
                    services.append(service_info)
        
        return {
            'services': services,
            'total_services': len(services)
        }
    
    def _parse_vulnerability_output(self, output: str) -> Dict:
        """Parse la sortie du scan de vulnérabilités"""
        vulnerabilities = []
        current_port = None
        
        lines = output.split('\n')
        for line in lines:
            # Nouveau port
            if '/' in line and 'open' in line:
                port_match = re.search(r'(\d+/\w+)', line)
                if port_match:
                    current_port = port_match.group(1)
            
            # Script de vulnérabilité
            elif line.startswith('|') and current_port:
                script_line = line.strip('| ')
                if script_line and not script_line.startswith('_'):
                    vuln_info = {
                        'port': current_port,
                        'description': script_line,
                        'severity': self._extract_severity(script_line)
                    }
                    vulnerabilities.append(vuln_info)
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'high_severity': len([v for v in vulnerabilities if v['severity'] == 'high']),
            'medium_severity': len([v for v in vulnerabilities if v['severity'] == 'medium']),
            'low_severity': len([v for v in vulnerabilities if v['severity'] == 'low'])
        }
    
    def _extract_severity(self, description: str) -> str:
        """Extraire la sévérité d'une description de vulnérabilité"""
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['critical', 'high', 'severe', 'dangerous']):
            return 'high'
        elif any(word in desc_lower for word in ['medium', 'moderate', 'warning']):
            return 'medium'
        else:
            return 'low'
    
    def quick_scan(self, target: str) -> Dict:
        """
        Scan rapide combiné (discovery + ports communs + services)
        
        Args:
            target: IP, plage ou hostname
            
        Returns:
            Dict avec résultats combinés
        """
        try:
            logger.info(f"Nmap quick scan: {target}")
            
            # Scan rapide des ports les plus courants
            cmd = ['nmap', '-F', '-sV', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': result.stderr,
                    'raw_output': result.stdout
                }
            
            # Combiner les parsers
            port_data = self._parse_port_scan_output(result.stdout)
            service_data = self._parse_service_output(result.stdout)
            
            return {
                'success': True,
                'target': target,
                'scan_type': 'quick',
                'open_ports': port_data['open_ports'],
                'services': service_data['services'],
                'summary': {
                    'ports_found': len(port_data['open_ports']),
                    'services_identified': len(service_data['services'])
                },
                'raw_output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - scan trop long'
            }
        except Exception as e:
            logger.error(f"Erreur quick scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def validate_target(target: str) -> tuple[bool, str]:
        """
        Valide qu'une cible est au bon format
        
        Returns:
            (is_valid, message)
        """
        target = target.strip()
        
        # IP simple
        try:
            ipaddress.ip_address(target)
            return True, f"IP valide: {target}"
        except ValueError:
            pass
        
        # Plage CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return True, f"Plage IP valide: {target}"
        except ValueError:
            pass
        
        # Plage avec tiret
        if '-' in target:
            try:
                start_ip, end_ip = target.split('-')
                ipaddress.ip_address(start_ip.strip())
                ipaddress.ip_address(end_ip.strip())
                return True, f"Plage IP valide: {target}"
            except ValueError:
                pass
        
        # Hostname
        if target.replace('.', '').replace('-', '').isalnum():
            try:
                socket.gethostbyname(target)
                return True, f"Hostname résolvable: {target}"
            except (socket.gaierror, UnicodeError):
                return False, f"Hostname non résolvable: {target}"
        
        return False, f"Format invalide: {target}"

# backend/core/huntkit_tools.py
"""
Wrappers Python pour les outils HuntKit intégrés
Compatible avec l'architecture Celery existante
"""

import os
import subprocess
import json
import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class HuntKitToolsManager:
    """Gestionnaire centralisé pour tous les outils HuntKit"""
    
    def __init__(self):
        self.tools_dir = os.getenv('TOOLS_DIR', '/opt')
        self.wordlists_dir = os.getenv('WORDLISTS_DIR', '/usr/share/wordlists')
        
        # Chemins des outils
        self.tools_paths = {
            'nmap': '/usr/bin/nmap',
            'hydra': '/usr/local/bin/hydra',
            'nikto': '/usr/local/bin/nikto',
            'nuclei': '/usr/local/bin/nuclei',
            'sqlmap': '/usr/local/bin/sqlmap',
            'msfconsole': '/opt/metasploit-framework/embedded/framework/msfconsole'
        }
        
        # Wordlists communes
        self.wordlists = {
            'passwords': f'{self.wordlists_dir}/rockyou.txt',
            'common_passwords': f'{self.wordlists_dir}/top1000-passwords.txt',
            'common_dirs': f'{self.wordlists_dir}/common.txt'
        }
    
    def verify_tools(self) -> Dict[str, bool]:
        """Vérifie que tous les outils sont disponibles"""
        status = {}
        for tool, path in self.tools_paths.items():
            status[tool] = os.path.exists(path) or self._which(tool) is not None
        return status
    
    def _which(self, program: str) -> Optional[str]:
        """Équivalent de 'which' en Python"""
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
                return exe_file
        return None
    
    def _run_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Exécute une commande et retourne le résultat"""
        try:
            logger.info(f"🔧 Exécution: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False  # Ne pas lever d'exception sur code de retour non-zéro
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(command)
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Timeout ({timeout}s) pour: {' '.join(command)}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': f'Timeout après {timeout} secondes',
                'command': ' '.join(command)
            }
        except Exception as e:
            logger.error(f"❌ Erreur exécution: {e}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'command': ' '.join(command)
            }


class NmapWrapper:
    """Wrapper pour Nmap"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def ping_scan(self, target: str, timeout: int = 300) -> Dict[str, Any]:
        """Scan de découverte (ping scan)"""
        command = ['nmap', '-sn', '-PE', '-PP', '-PM', target]
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_ping_scan(result['stdout'])
        
        return result
    
    def port_scan(self, target: str, ports: str = '1-1000', timeout: int = 600) -> Dict[str, Any]:
        """Scan de ports"""
        command = ['nmap', '-sS', '-p', ports, target]
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_port_scan(result['stdout'])
        
        return result
    
    def service_scan(self, target: str, ports: str = '22,80,443', timeout: int = 900) -> Dict[str, Any]:
        """Scan des services et versions"""
        command = ['nmap', '-sV', '-sC', '-p', ports, target]
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_service_scan(result['stdout'])
        
        return result
    
    def _parse_ping_scan(self, output: str) -> Dict[str, Any]:
        """Parse la sortie d'un ping scan"""
        hosts = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Nmap scan report for' in line:
                # Extraire l'IP/hostname
                parts = line.split('Nmap scan report for ')
                if len(parts) > 1:
                    host_info = parts[1].strip()
                    hosts.append({'host': host_info, 'status': 'up'})
        
        return {
            'hosts_found': hosts,
            'total_hosts': len(hosts)
        }
    
    def _parse_port_scan(self, output: str) -> Dict[str, Any]:
        """Parse la sortie d'un port scan"""
        return {'raw_output': output}  # Parsing détaillé à implémenter selon besoins
    
    def _parse_service_scan(self, output: str) -> Dict[str, Any]:
        """Parse la sortie d'un service scan"""
        return {'raw_output': output}  # Parsing détaillé à implémenter selon besoins


class HydraWrapper:
    """Wrapper pour Hydra"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def brute_force(self, target: str, service: str, username: str = None, 
                   userlist: str = None, password: str = None, 
                   passwordlist: str = None, timeout: int = 1800) -> Dict[str, Any]:
        """Attaque par force brute"""
        
        command = ['hydra']
        
        # Utilisateur(s)
        if username:
            command.extend(['-l', username])
        elif userlist:
            command.extend(['-L', userlist])
        else:
            command.extend(['-l', 'admin'])  # Valeur par défaut
        
        # Mot(s) de passe
        if password:
            command.extend(['-p', password])
        elif passwordlist:
            command.extend(['-P', passwordlist])
        else:
            # Utiliser la wordlist par défaut
            default_wordlist = self.tools.wordlists.get('common_passwords')
            if os.path.exists(default_wordlist):
                command.extend(['-P', default_wordlist])
            else:
                command.extend(['-p', 'password'])  # Fallback
        
        # Cible et service
        command.extend([target, service])
        
        # Options additionnelles
        command.extend(['-t', '4', '-f'])  # 4 threads, arrêt à la première trouvaille
        
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_hydra_output(result['stdout'])
        
        return result
    
    def _parse_hydra_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Hydra"""
        found_credentials = []
        lines = output.split('\n')
        
        for line in lines:
            if '[' in line and '] login:' in line and 'password:' in line:
                # Format: [service][port] host: login: password:
                try:
                    parts = line.split('] ')[1]  # Après le premier ]
                    if 'login:' in parts and 'password:' in parts:
                        login_part = parts.split('login:')[1].split('password:')[0].strip()
                        password_part = parts.split('password:')[1].strip()
                        
                        found_credentials.append({
                            'login': login_part,
                            'password': password_part
                        })
                except:
                    continue
        
        return {
            'credentials_found': found_credentials,
            'total_found': len(found_credentials)
        }


class NiktoWrapper:
    """Wrapper pour Nikto"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def web_scan(self, target: str, port: int = 80, ssl: bool = False, 
                timeout: int = 1800) -> Dict[str, Any]:
        """Scan de vulnérabilités web"""
        
        # Construire l'URL
        protocol = 'https' if ssl else 'http'
        if port != (443 if ssl else 80):
            url = f"{protocol}://{target}:{port}"
        else:
            url = f"{protocol}://{target}"
        
        command = [
            'nikto',
            '-h', url,
            '-Format', 'txt',
            '-timeout', '10'
        ]
        
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_nikto_output(result['stdout'])
        
        return result
    
    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Nikto"""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if line.startswith('+ ') and ':' in line:
                vulnerabilities.append(line[2:].strip())  # Retirer '+ '
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }


class NucleiWrapper:
    """Wrapper pour Nuclei"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def vulnerability_scan(self, target: str, templates: str = None, 
                          severity: str = None, timeout: int = 1800) -> Dict[str, Any]:
        """Scan de vulnérabilités avec Nuclei"""
        
        command = ['nuclei', '-u', target, '-json']
        
        # Templates spécifiques
        if templates:
            command.extend(['-t', templates])
        
        # Sévérité
        if severity:
            command.extend(['-severity', severity])
        
        # Mise à jour des templates si nécessaire
        command.extend(['-update-templates'])
        
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_nuclei_output(result['stdout'])
        
        return result
    
    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie JSON de Nuclei"""
        vulnerabilities = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if line.strip():
                try:
                    vuln_data = json.loads(line)
                    vulnerabilities.append(vuln_data)
                except json.JSONDecodeError:
                    continue
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }


class SQLMapWrapper:
    """Wrapper pour SQLMap"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def sql_injection_scan(self, target: str, data: str = None, 
                          cookie: str = None, timeout: int = 1800) -> Dict[str, Any]:
        """Scan d'injection SQL"""
        
        command = ['sqlmap', '-u', target, '--batch', '--random-agent']
        
        # Données POST
        if data:
            command.extend(['--data', data])
        
        # Cookies
        if cookie:
            command.extend(['--cookie', cookie])
        
        # Options de base
        command.extend(['--level=1', '--risk=1'])
        
        result = self.tools._run_command(command, timeout)
        
        if result['success']:
            result['parsed'] = self._parse_sqlmap_output(result['stdout'])
        
        return result
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de SQLMap"""
        # Rechercher les paramètres vulnérables
        vulnerable_params = []
        
        if 'parameter' in output.lower() and 'vulnerable' in output.lower():
            # Parsing basique - à améliorer selon les besoins
            vulnerable_params.append("Paramètre vulnérable détecté")
        
        return {
            'vulnerable_parameters': vulnerable_params,
            'injection_found': len(vulnerable_params) > 0
        }


# ===== CLASSE PRINCIPALE =====
class HuntKitIntegration:
    """Intégration principale pour utiliser HuntKit avec Celery"""
    
    def __init__(self):
        self.tools_manager = HuntKitToolsManager()
        self.nmap = NmapWrapper(self.tools_manager)
        self.hydra = HydraWrapper(self.tools_manager)
        self.nikto = NiktoWrapper(self.tools_manager)
        self.nuclei = NucleiWrapper(self.tools_manager)
        self.sqlmap = SQLMapWrapper(self.tools_manager)
    
    def get_tool_status(self) -> Dict[str, Any]:
        """Retourne le statut de tous les outils"""
        return {
            'tools_available': self.tools_manager.verify_tools(),
            'wordlists': self.tools_manager.wordlists,
            'tools_dir': self.tools_manager.tools_dir,
            'initialized_at': datetime.now().isoformat()
        }
    
    def run_discovery(self, target: str) -> Dict[str, Any]:
        """Lance une découverte réseau complète - VERSION CORRIGÉE"""
        logger.info(f"🌐 Début découverte réseau: {target}")
        
        # 1. Ping scan pour découvrir les hôtes
        ping_result = self.nmap.ping_scan(target)
        
        if not ping_result['success']:
            return {
                'success': False,
                'error': f"Échec du ping scan: {ping_result['stderr']}",
                'target': target
            }
        
        # 2. Port scan sur les hôtes découverts
        port_results = []
        discovered_hosts = ping_result.get('parsed', {}).get('hosts_found', [])
        
        for host in discovered_hosts[:5]:  # Limiter à 5 hôtes max
            host_target = host['host']
            
            # ✅ FIX: Extraire seulement l'IP du nom d'hôte complexe
            if '(' in host_target and ')' in host_target:
                # Extraire l'IP entre parenthèses: "nom (192.168.1.1)" -> "192.168.1.1"
                ip_match = re.search(r'\(([0-9.]+)\)', host_target)
                if ip_match:
                    host_target = ip_match.group(1)
            
            logger.info(f"🔍 Scan de ports sur: {host_target}")
            
            docker_ports = '21,22,23,25,53,80,135,139,443,445,993,995,1433,1723,3000,3306,3389,4369,5000,5432,5555,5672,5984,6379,8000,8080,8443,8888,9000,9042,9200,9300,11211,27017,27018,27019,28017'
            port_result = self.nmap.port_scan(host_target, docker_ports)
            port_results.append({
                'host': host_target,
                'original_host': host['host'],  # Garder le nom original
                'ports': port_result
            })
        
        return {
            'success': True,
            'target': target,
            'ping_scan': ping_result,
            'port_scans': port_results,
            'summary': {
                'hosts_discovered': len(discovered_hosts),
                'hosts_scanned': len(port_results)
            }
        }
    
    def run_web_audit(self, target: str, port: int = 80, ssl: bool = False) -> Dict[str, Any]:
        """Lance un audit web complet"""
        logger.info(f"🕷️ Début audit web: {target}:{port}")
        
        results = {}
        
        # 1. Nikto scan
        nikto_result = self.nikto.web_scan(target, port, ssl)
        results['nikto'] = nikto_result
        
        # 2. Nuclei scan
        protocol = 'https' if ssl else 'http'
        url = f"{protocol}://{target}:{port}"
        nuclei_result = self.nuclei.vulnerability_scan(url, severity='medium,high,critical')
        results['nuclei'] = nuclei_result
        
        # 3. SQLMap scan (sur l'URL de base)
        sqlmap_result = self.sqlmap.sql_injection_scan(url)
        results['sqlmap'] = sqlmap_result
        
        return {
            'success': True,
            'target': f"{target}:{port}",
            'ssl': ssl,
            'results': results,
            'summary': {
                'nikto_vulns': len(results['nikto'].get('parsed', {}).get('vulnerabilities', [])),
                'nuclei_vulns': len(results['nuclei'].get('parsed', {}).get('vulnerabilities', [])),
                'sql_injection': results['sqlmap'].get('parsed', {}).get('injection_found', False)
            }
        }
    
    def run_brute_force(self, target: str, service: str, userlist: str = None, 
                       passwordlist: str = None) -> Dict[str, Any]:
        """Lance une attaque par force brute"""
        logger.info(f"🔨 Début force brute: {target} ({service})")
        
        # Utiliser les wordlists par défaut si non spécifiées
        if not passwordlist:
            passwordlist = self.tools_manager.wordlists.get('common_passwords')
        
        result = self.hydra.brute_force(
            target=target,
            service=service,
            userlist=userlist,
            passwordlist=passwordlist
        )
        
        return {
            'success': result['success'],
            'target': target,
            'service': service,
            'result': result,
            'credentials_found': result.get('parsed', {}).get('credentials_found', [])
        }

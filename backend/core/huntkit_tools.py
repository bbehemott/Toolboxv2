import os
import subprocess
import json
import logging
import re
import tempfile
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
    
    def _run_command(self, command: List[str], timeout: int = 300, input_data: str = None) -> Dict[str, Any]:
        """Exécute une commande et retourne le résultat - VERSION AMÉLIORÉE"""
        try:
            logger.info(f"🔧 Exécution: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data,
                check=False  # Ne pas lever d'exception sur code de retour non-zéro
            )
            
            logger.info(f"📊 Code retour: {result.returncode}")
            logger.debug(f"📝 Stdout ({len(result.stdout)} chars): {result.stdout[:200]}...")
            logger.debug(f"📝 Stderr ({len(result.stderr)} chars): {result.stderr[:200]}...")
            
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
    """Wrapper pour Nikto - VERSION CORRIGÉE"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def web_scan(self, target: str, port: int = 80, ssl: bool = False, 
                timeout: int = 1800) -> Dict[str, Any]:
        """Scan de vulnérabilités web - VERSION CORRIGÉE"""
        
        protocol = 'https' if ssl else 'http'
        default_port = 443 if ssl else 80
        
        if port == default_port:
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port}"
        
        # 🔥 CORRECTION: Retirer -Format txt qui cause l'erreur
        command = [
            'nikto',
            '-h', url,
            '-timeout', '15',
            '-maxtime', '600',
            '-nointeractive'
        ]
        
        logger.info(f"🕷️ Commande Nikto: {' '.join(command)}")
        
        result = self.tools._run_command(command, timeout)
        
        # Debug : afficher stderr si erreur
        if not result['success']:
            logger.error(f"❌ Nikto stderr: {result['stderr']}")
        
        result['parsed'] = self._parse_nikto_output(result['stdout'])
        
        return result
    
    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Nikto - VERSION AMÉLIORÉE"""
        vulnerabilities = []
        lines = output.split('\n')
        
        logger.info(f"📝 Nikto: {len(lines)} lignes à analyser")
        
        for line in lines:
            line = line.strip()
            
            # Lignes qui commencent par + sont des vulnérabilités/informations
            if line.startswith('+ ') and len(line) > 2:
                vuln = line[2:].strip()  # Retirer '+ '
                # Filtrer les lignes d'info non importantes
                if vuln and not any(skip in vuln.lower() for skip in [
                    'target ip:', 'target hostname:', 'target port:', 'start time:'
                ]):
                    vulnerabilities.append(vuln)
                    logger.debug(f"🕷️ Vulnérabilité Nikto: {vuln[:100]}...")
        
        logger.info(f"🕷️ Nikto: {len(vulnerabilities)} vulnérabilités trouvées")
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }


class NucleiWrapper:
    """Wrapper pour Nuclei - VERSION CORRIGÉE"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def vulnerability_scan(self, target: str, templates: str = None, 
                          severity: str = None, timeout: int = 1800) -> Dict[str, Any]:
        """Scan de vulnérabilités avec Nuclei - VERSION CORRIGÉE"""
        
        # 🔥 CORRECTION: Utiliser -jsonl au lieu de -json
        command = ['nuclei', '-u', target, '-jsonl', '-silent']
        
        # Templates
        if templates:
            command.extend(['-t', templates])
        
        # Sévérité
        if severity:
            command.extend(['-severity', severity])
        else:
            command.extend(['-severity', 'medium,high,critical'])
        
        # Options corrigées
        command.extend([
            '-timeout', '10',
            '-retries', '1',
            '-no-color'
        ])
        
        logger.info(f"🎯 Commande Nuclei: {' '.join(command)}")
        
        result = self.tools._run_command(command, timeout)
        
        if result['returncode'] != 0:
            logger.warning(f"⚠️ Nuclei stderr: {result['stderr']}")
        
        result['parsed'] = self._parse_nuclei_output(result['stdout'])
        
        return result
    
    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie JSON de Nuclei - VERSION AMÉLIORÉE"""
        vulnerabilities = []
        lines = output.strip().split('\n')
        
        logger.info(f"📝 Nuclei: {len(lines)} lignes à parser")
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                # Tenter de parser chaque ligne comme JSON
                vuln_data = json.loads(line)
                vulnerabilities.append(vuln_data)
                logger.debug(f"✅ Ligne {line_num}: {vuln_data.get('template-id', 'unknown')}")
                
            except json.JSONDecodeError as e:
                # Si ce n'est pas du JSON, peut-être un message d'erreur ou d'info
                logger.debug(f"⚠️ Ligne {line_num} non-JSON: {line[:50]}...")
                continue
        
        logger.info(f"🎯 Nuclei: {len(vulnerabilities)} vulnérabilités trouvées")
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'raw_lines': len(lines)
        }


class SQLMapWrapper:
    """Wrapper pour SQLMap - VERSION CORRIGÉE"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
    
    def sql_injection_scan(self, target: str, data: str = None, 
                          cookie: str = None, timeout: int = 1800) -> Dict[str, Any]:
        """Scan d'injection SQL - VERSION CORRIGÉE POUR DVWA"""
        
        # 🔥 CORRECTION: URL spécifique DVWA avec authentification
        if '172.20.0.4' in target:
            # DVWA nécessite d'être connecté
            if 'vulnerabilities' not in target:
                test_url = f"{target.rstrip('/')}/vulnerabilities/sqli/?id=1&Submit=Submit"
            else:
                test_url = target if '?' in target else f"{target}?id=1&Submit=Submit"
            
            # Cookie avec session et sécurité basse
            dvwa_cookie = "security=low; PHPSESSID=dvwatest123"
        else:
            test_url = target if '?' in target else f"{target.rstrip('/')}?id=1&Submit=Submit"
            dvwa_cookie = cookie
        
        command = ['sqlmap', '-u', test_url, '--batch', '--random-agent']
        
        # Cookie DVWA obligatoire
        if dvwa_cookie:
            command.extend(['--cookie', dvwa_cookie])
        
        # 🔥 CORRECTION: Paramètres plus agressifs pour DVWA
        command.extend([
            '--level=5',           # Niveau maximum
            '--risk=3',            # Risque maximum
            '--timeout=5',         
            '--retries=1',         
            '--technique=BEUSTQ',  # Toutes les techniques
            '--flush-session',     
            '--fresh-queries',
            '--forms',             # Détecter les formulaires
            '--crawl=2'            # Explorer 2 niveaux
        ])
        
        logger.info(f"💉 Commande SQLMap: {' '.join(command)}")
        logger.info(f"💉 URL testée: {test_url}")
        
        result = self.tools._run_command(command, timeout)
        
        # Toujours parser même si pas d'injection trouvée
        result['parsed'] = self._parse_sqlmap_output(result['stdout'] + result['stderr'])
        
        return result
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de SQLMap - VERSION AMÉLIORÉE"""
        
        # Rechercher les indicateurs d'injection
        vulnerable_params = []
        injection_types = []
        
        lines = output.split('\n')
        logger.info(f"📝 SQLMap: {len(lines)} lignes à analyser")
        
        for line in lines:
            line_lower = line.lower()
            
            # Détection d'injections
            if 'parameter' in line_lower and 'vulnerable' in line_lower:
                vulnerable_params.append(line.strip())
                logger.info(f"🚨 Paramètre vulnérable: {line.strip()}")
            
            # Types d'injection détectés
            if 'type:' in line_lower and any(x in line_lower for x in ['boolean', 'time', 'union', 'error', 'stacked']):
                injection_types.append(line.strip())
                logger.info(f"💉 Type d'injection: {line.strip()}")
            
            # Indicateurs de succès plus larges
            success_indicators = [
                'sqlmap identified',
                'injection point',
                'database management system',
                'back-end dbms',
                'appears to be',
                'seems to be',
                'might be injectable'
            ]
            
            if any(keyword in line_lower for keyword in success_indicators):
                logger.info(f"✅ Indicateur positif: {line.strip()}")
                if 'appears to be' in line_lower or 'seems to be' in line_lower:
                    vulnerable_params.append(f"Détection: {line.strip()}")
        
        # Analyser le niveau de confiance
        injection_found = len(vulnerable_params) > 0 or len(injection_types) > 0
        
        logger.info(f"💉 SQLMap résultat: injection_found={injection_found}, vulns={len(vulnerable_params)}")
        
        return {
            'vulnerable_parameters': vulnerable_params,
            'injection_types': injection_types,
            'injection_found': injection_found,
            'raw_analysis': f"Analysé {len(lines)} lignes, trouvé {len(vulnerable_params)} indicateurs"
        }


# ===== CLASSE PRINCIPALE =====
class HuntKitIntegration:
    """Intégration principale pour utiliser HuntKit avec Celery - VERSION COMPLÈTE CORRIGÉE"""
    
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
        """Lance un audit web complet - VERSION CORRIGÉE"""
        logger.info(f"🕷️ Début audit web: {target}:{port} (SSL: {ssl})")
        
        results = {}
        
        # 1. Nikto scan
        logger.info("🕷️ Lancement Nikto...")
        nikto_result = self.nikto.web_scan(target, port, ssl)
        results['nikto'] = nikto_result
        logger.info(f"🕷️ Nikto terminé: {nikto_result.get('parsed', {}).get('total_vulnerabilities', 0)} vulns")
        
        # 2. Nuclei scan
        logger.info("🎯 Lancement Nuclei...")
        protocol = 'https' if ssl else 'http'
        url = f"{protocol}://{target}:{port}"
        nuclei_result = self.nuclei.vulnerability_scan(url)
        results['nuclei'] = nuclei_result
        logger.info(f"🎯 Nuclei terminé: {nuclei_result.get('parsed', {}).get('total_vulnerabilities', 0)} vulns")
        
        # 3. SQLMap scan (sur l'URL de base)
        logger.info("💉 Lancement SQLMap...")
        sqlmap_result = self.sqlmap.sql_injection_scan(url)
        results['sqlmap'] = sqlmap_result
        logger.info(f"💉 SQLMap terminé: injection = {sqlmap_result.get('parsed', {}).get('injection_found', False)}")
        
        # Calculer le résumé
        nikto_vulns = results['nikto'].get('parsed', {}).get('total_vulnerabilities', 0)
        nuclei_vulns = results['nuclei'].get('parsed', {}).get('total_vulnerabilities', 0)
        sql_injection = results['sqlmap'].get('parsed', {}).get('injection_found', False)
        
        return {
            'success': True,
            'target': f"{target}:{port}",
            'ssl': ssl,
            'results': results,
            'summary': {
                'nikto_vulns': nikto_vulns,
                'nuclei_vulns': nuclei_vulns,
                'sql_injection': sql_injection,
                'total_issues': nikto_vulns + nuclei_vulns + (1 if sql_injection else 0)
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

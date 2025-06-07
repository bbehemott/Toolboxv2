from flask import Blueprint, request, render_template, session, current_app, jsonify
from auth import login_required, pentester_required, admin_required
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

@huntkit_bp.route('/sessions')
@login_required
def sessions_page():
    """Page de gestion des sessions actives"""
    return render_template('huntkit/sessions.html')

@huntkit_bp.route('/sessions/<int:session_id>')
@login_required
def session_detail_page(session_id):
    """Page de détail d'une session avec webshell"""
    return render_template('huntkit/session_detail.html', session_id=session_id)

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


@huntkit_bp.route('/api/sessions/active')
@login_required
def api_active_sessions():
    """API pour récupérer les sessions actives"""
    try:
        from services.session_manager import SessionManager
        session_manager = SessionManager(current_app.db)
        
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Admin voit toutes les sessions, autres seulement les leurs
        if user_role == 'admin':
            sessions = session_manager.get_active_sessions()
        else:
            sessions = session_manager.get_active_sessions(user_id=user_id)
        
        return {
            'success': True,
            'sessions': sessions,
            'total': len(sessions)
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur récupération sessions actives: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/sessions/<int:session_id>/info')
@login_required
def api_session_info(session_id):
    """API pour récupérer les détails d'une session"""
    try:
        from services.session_manager import SessionManager
        session_manager = SessionManager(current_app.db)
        
        # Vérifier l'accès utilisateur
        session_info = session_manager.get_session_info(session_id)
        if not session_info:
            return {
                'success': False,
                'error': 'Session non trouvée'
            }, 404
        
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if user_role != 'admin' and session_info.get('user_id') != user_id:
            return {
                'success': False,
                'error': 'Accès refusé'
            }, 403
        
        # Récupérer les actions de post-exploitation
        actions = session_manager.get_session_actions(session_id)
        
        return {
            'success': True,
            'session': session_info,
            'actions': actions,
            'can_take_control': session_info.get('manual_takeover_enabled', False)
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur info session {session_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/sessions/<int:session_id>/execute', methods=['POST'])
@login_required
def api_session_execute_command(session_id):
    """API pour exécuter une commande sur une session - VERSION CORRIGÉE"""
    try:
        from services.session_manager import SessionManager
        session_manager = SessionManager(current_app.db)
        
        # Vérifier l'accès utilisateur
        session_info = session_manager.get_session_info(session_id)
        if not session_info:
            return {
                'success': False,
                'error': 'Session non trouvée'
            }, 404
        
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if user_role != 'admin' and session_info.get('user_id') != user_id:
            return {
                'success': False,
                'error': 'Accès refusé'
            }, 403
        
        # Vérifier que la prise de contrôle manuelle est activée
        if not session_info.get('manual_takeover_enabled', False):
            return {
                'success': False,
                'error': 'Prise de contrôle manuelle non encore activée'
            }, 400
        
        data = request.get_json()
        command = data.get('command', '').strip()
        
        if not command:
            return {
                'success': False,
                'error': 'Commande requise'
            }, 400
        
        # Commandes interdites pour sécurité
        forbidden_commands = ['rm -rf', 'format', 'del /s', 'shutdown', 'reboot']
        if any(forbidden in command.lower() for forbidden in forbidden_commands):
            return {
                'success': False,
                'error': 'Commande interdite pour sécurité'
            }, 400
        
        # ✅ CORRECTION PRINCIPALE : Utiliser le vrai session_id de Metasploit
        metasploit_session_id = session_info['session_id']  # ID réel de Metasploit
        
        logger.info(f"🔧 Commande manuelle: {command} sur session MSF #{metasploit_session_id} (DB ID: {session_id})")
        
        # Exécuter la commande avec le bon ID
        from core.huntkit_tools import HuntKitIntegration
        huntkit = HuntKitIntegration()
        
        result = huntkit.metasploit.execute_session_command(
            metasploit_session_id, command  # ✅ Utiliser le bon ID Metasploit
        )
        
        # Enregistrer la commande manuelle
        action_id = session_manager._create_post_exploit_action(
            session_id, 'manual_command', command
        )
        
        if action_id:
            session_manager._update_post_exploit_action(
                action_id, 'completed' if result['success'] else 'failed',
                result_data=result,
                raw_output=result.get('output'),
                error_message=result.get('error')
            )
        
        return {
            'success': True,
            'command': command,
            'result': result,
            'session_info': {
                'db_id': session_id,
                'metasploit_id': metasploit_session_id
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur exécution commande session {session_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@huntkit_bp.route('/api/sessions/<int:session_id>/close', methods=['POST'])
@login_required
def api_close_session(session_id):
    """API pour fermer une session"""
    try:
        from services.session_manager import SessionManager
        session_manager = SessionManager(current_app.db)
        
        # Vérifier l'accès utilisateur
        session_info = session_manager.get_session_info(session_id)
        if not session_info:
            return {
                'success': False,
                'error': 'Session non trouvée'
            }, 404
        
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if user_role != 'admin' and session_info.get('user_id') != user_id:
            return {
                'success': False,
                'error': 'Accès refusé'
            }, 403
        
        # Fermer la session en base
        current_app.db.update_session_status(session_id, 'closed')
        
        # Optionnel: Tenter de fermer dans Metasploit aussi
        try:
            from core.huntkit_tools import HuntKitIntegration
            huntkit = HuntKitIntegration()
            huntkit.metasploit.execute_session_command(
                session_info['session_id'], 'exit'
            )
        except Exception as e:
            logger.warning(f"⚠️ Impossible de fermer session Metasploit: {e}")
        
        logger.info(f"🔴 Session {session_id} fermée par utilisateur {user_id}")
        
        return {
            'success': True,
            'message': 'Session fermée avec succès'
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur fermeture session {session_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/sessions/sync', methods=['POST'])
@login_required
def api_sync_metasploit_sessions():
    """API pour synchroniser avec les sessions Metasploit actives"""
    try:
        from core.huntkit_tools import HuntKitIntegration
        from services.session_manager import SessionManager
        
        huntkit = HuntKitIntegration()
        session_manager = SessionManager(current_app.db)
        
        # Récupérer les sessions actives depuis Metasploit
        msf_sessions = huntkit.metasploit.get_active_sessions()
        
        if not msf_sessions['success']:
            return {
                'success': False,
                'error': f"Erreur Metasploit: {msf_sessions.get('error', 'Inconnu')}"
            }, 500
        
        # Synchroniser avec la base
        synced_count = 0
        new_sessions = []
        
        for msf_session in msf_sessions['sessions']:
            # Vérifier si cette session existe déjà en base
            existing = current_app.db.get_connection()
            with existing as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id FROM metasploit_sessions 
                    WHERE session_id = %s AND status = 'active'
                ''', (msf_session['session_id'],))
                
                if not cursor.fetchone():
                    # Nouvelle session trouvée
                    db_session_id = session_manager.register_session(
                        session_id=msf_session['session_id'],
                        task_id=None,  # Session externe
                        target_ip=msf_session.get('target_ip', 'unknown'),
                        target_port=None,
                        session_type=msf_session['session_type'],
                        platform=msf_session.get('platform'),
                        user_id=session.get('user_id')
                    )
                    
                    if db_session_id:
                        new_sessions.append({
                            'db_id': db_session_id,
                            'session_id': msf_session['session_id'],
                            'session_type': msf_session['session_type']
                        })
                        synced_count += 1
        
        return {
            'success': True,
            'message': f'Synchronisation terminée: {synced_count} nouvelle(s) session(s)',
            'synced_count': synced_count,
            'new_sessions': new_sessions,
            'total_msf_sessions': len(msf_sessions['sessions'])
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur synchronisation Metasploit: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/sessions/statistics')
@login_required
def api_sessions_statistics():
    """API pour les statistiques des sessions"""
    try:
        stats = current_app.db.get_sessions_statistics()
        
        return {
            'success': True,
            'statistics': stats
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur statistiques sessions: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@huntkit_bp.route('/api/sessions/cleanup', methods=['POST'])
@admin_required
def api_cleanup_old_sessions():
    """API pour nettoyer les anciennes sessions (admin seulement)"""
    try:
        data = request.get_json() if request.is_json else {}
        days = data.get('days', 7)
        
        if not isinstance(days, (int, float)) or days < 0:
            return {
                'success': False,
                'error': 'Paramètre days invalide'
            }, 400
        
        cleaned_count = current_app.db.cleanup_old_sessions(int(days))
        
        return {
            'success': True,
            'message': f'Nettoyage terminé: {cleaned_count} session(s) supprimée(s)',
            'cleaned_count': cleaned_count,
            'days': days
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur nettoyage sessions: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500



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

# ===== FONCTIONS DE VALIDATION (INCHANGÉES) =====

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

# ===== INFORMATION ET AIDE (INCHANGÉES) =====

@huntkit_bp.route('/api/info')
@login_required
def api_huntkit_info():
    """Informations sur l'intégration HuntKit - VERSION AVEC SESSIONS"""
    return {
        'success': True,
        'info': {
            'name': 'HuntKit Integration avec Post-Exploitation',
            'version': '2.0',
            'description': 'Intégration complète HuntKit + Metasploit avec post-exploitation automatique',
            'tools_included': [
                {'name': 'Nmap', 'purpose': 'Découverte réseau et scan de ports'},
                {'name': 'Hydra', 'purpose': 'Attaques par force brute'},
                {'name': 'Nikto', 'purpose': 'Scan de vulnérabilités web'},
                {'name': 'Nuclei', 'purpose': 'Détection de vulnérabilités automatisée'},
                {'name': 'SQLMap', 'purpose': 'Détection et exploitation d\'injections SQL'},
                {'name': 'Metasploit', 'purpose': 'Framework d\'exploitation avec post-exploitation automatique'}
            ],
            'new_features': [
                {'name': 'Détection automatique de sessions', 'description': 'Détection et enregistrement automatique des sessions ouvertes'},
                {'name': 'Post-exploitation automatique', 'description': 'Scénario automatisé d\'énumération après exploitation'},
                {'name': 'Webshell interactif', 'description': 'Contrôle manuel des sessions via interface web'},
                {'name': 'Gestion centralisée', 'description': 'Dashboard unifié pour toutes les sessions actives'}
            ],
            'post_exploit_actions': [
                'Informations système (sysinfo)',
                'Utilisateur actuel (getuid)',
                'Processus en cours (ps)',
                'Dump des hashs (hashdump - Meterpreter)',
                'Scan réseau interne (ping_sweep)'
            ],
            'session_types_supported': ['meterpreter', 'shell', 'powershell', 'cmd'],
            'estimated_times': {
                'session_detection': 'Instantané',
                'auto_post_exploitation': '30-120 secondes',
                'manual_takeover': 'Disponible après post-exploitation'
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

logger.info("🔧 Module HuntKit routes chargé avec suppressions selon plan d'action")

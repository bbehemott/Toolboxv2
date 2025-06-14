from flask import Blueprint, request, render_template, session, current_app, jsonify
from auth import login_required, admin_required
from services.task_manager import TaskManager
from flask import send_file
from .report_exporter import ImprovedReportExporter
import os
import logging
import json

logger = logging.getLogger('toolbox.tasks')

tasks_bp = Blueprint('tasks', __name__)

# ===== PAGES DE MONITORING =====

@tasks_bp.route('/dashboard')
@login_required
def tasks_dashboard():
    """Dashboard de toutes les tâches"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Admin voit toutes les tâches, autres utilisateurs seulement les leurs
        if user_role == 'admin':
            tasks = current_app.db.get_tasks(include_hidden=False, limit=50)
        else:
            tasks = current_app.db.get_tasks(user_id=user_id, include_hidden=False, limit=50)
        
        logger.info(f"Dashboard tâches: {len(tasks)} tâches trouvées pour user {user_id} (role: {user_role})")
        
        return render_template('tasks/dashboard.html', tasks=tasks)
        
    except Exception as e:
        logger.error(f"Erreur dashboard tâches: {e}")
        return render_template('tasks/dashboard.html', tasks=[])


@tasks_bp.route('/<task_id>/status')
@login_required
def task_status(task_id):
    """Page de monitoring d'une tâche spécifique"""
    return render_template('tasks/status.html', task_id=task_id)

@tasks_bp.route('/<task_id>/results')
@login_required
def task_results(task_id):
    """Page des résultats d'une tâche"""
    try:
        task_manager = TaskManager(current_app.db)
        results = task_manager.get_task_results(task_id)
        
        if not results:
            return "Tâche non trouvée", 404
        
        return render_template('tasks/results.html', 
                             task_id=task_id, 
                             results=results)
        
    except Exception as e:
        logger.error(f"Erreur résultats tâche {task_id}: {e}")
        return "Erreur lors de la récupération des résultats", 500

# ===== API ENDPOINTS =====

@tasks_bp.route('/api/<task_id>/status')
@login_required
def api_task_status(task_id):
    """API pour récupérer le statut d'une tâche - VERSION CORRIGÉE"""
    try:
        task_manager = TaskManager(current_app.db)
        
        status = task_manager.get_task_status(task_id)
        
        if not status:
            return {
                'success': False,
                'error': 'Tâche non trouvée',
                'state': 'NOT_FOUND'
            }, 404
        
        response = {
            'success': True,
            'task_id': task_id,
            'state': status.get('unified_state', status.get('celery_state', 'UNKNOWN')),
            'status': status.get('unified_status', 'État inconnu'),
            'progress': status.get('unified_progress', 0),
            
            # Informations détaillées
            'meta': {
                'target': status.get('target'),
                'phase': status.get('celery_info', {}).get('phase', 'N/A'),
                'task_name': status.get('task_name'),
                'task_type': status.get('task_type')
            },
            
            # Timestamps
            'started_at': status.get('started_at'),
            'completed_at': status.get('completed_at'),
            
            # Résultats si terminé
            'result': status.get('result') if status.get('unified_state') == 'SUCCESS' else None,
            'error': status.get('error') if status.get('unified_state') == 'FAILURE' else None
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Erreur API statut tâche {task_id}: {e}")
        return {
            'success': False,
            'error': str(e),
            'state': 'ERROR'
        }, 500

@tasks_bp.route('/status/<task_id>')
@login_required
def task_status_page(task_id):
    """Page de monitoring d'une tâche"""
    return render_template('tasks/status.html', task_id=task_id)


@tasks_bp.route('/api/<task_id>/results')
@login_required  
def api_task_results(task_id):
    """API pour récupérer les résultats d'une tâche terminée"""
    try:
        task_manager = TaskManager(current_app.db)
        results = task_manager.get_task_results(task_id)
        
        if not results:
            return {
                'success': False,
                'error': 'Résultats non disponibles'
            }, 404
            
        return {
            'success': True,
            'results': results,
            'task_id': task_id
        }
        
    except Exception as e:
        logger.error(f"Erreur résultats tâche {task_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500




@tasks_bp.route('/api/<task_id>/cancel', methods=['POST'])
@login_required
def api_cancel_task(task_id):
    """API pour annuler une tâche"""
    try:
        task_manager = TaskManager(current_app.db)
        
        # Vérifier que l'utilisateur peut annuler cette tâche
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if not task_manager.can_user_access_task(task_id, user_id, user_role):
            return {
                'success': False,
                'error': 'Accès refusé'
            }, 403
        
        success = task_manager.cancel_task(task_id)
        
        if success:
            return {
                'success': True,
                'message': 'Tâche annulée'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible d\'annuler la tâche'
            }
            
    except Exception as e:
        logger.error(f"Erreur annulation tâche {task_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@tasks_bp.route('/api/<task_id>/hide', methods=['POST'])
@login_required
def api_hide_task(task_id):
    """API pour masquer une tâche de l'historique"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Vérifier les droits
        task_manager = TaskManager(current_app.db)
        if not task_manager.can_user_access_task(task_id, user_id, user_role):
            return {
                'success': False,
                'error': 'Accès refusé'
            }, 403
        
        success = current_app.db.hide_task(task_id)
        
        if success:
            return {
                'success': True,
                'message': 'Tâche masquée de l\'historique'
            }
        else:
            return {
                'success': False,
                'error': 'Tâche non trouvée'
            }
            
    except Exception as e:
        logger.error(f"Erreur masquage tâche {task_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@tasks_bp.route('/api/list')
@login_required
def api_list_tasks():
    """API pour lister les tâches"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Paramètres de pagination et filtrage
        limit = request.args.get('limit', 20, type=int)
        include_hidden = request.args.get('include_hidden', False, type=bool)
        active_only = request.args.get('active_only', False, type=bool)
        
        # Admin voit toutes les tâches
        if user_role == 'admin' and request.args.get('all_users', False, type=bool):
            tasks = current_app.db.get_tasks(
                include_hidden=include_hidden,
                limit=limit
            )
        else:
            tasks = current_app.db.get_tasks(
                user_id=user_id,
                include_hidden=include_hidden,
                limit=limit
            )
        
        # Filtrer les tâches actives si demandé
        if active_only:
            active_statuses = ['running', 'pending', 'started']
            tasks = [task for task in tasks if task.get('status') in active_statuses]
        
        return {
            'success': True,
            'tasks': tasks,
            'count': len(tasks)
        }
        
    except Exception as e:
        logger.error(f"Erreur liste tâches: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@tasks_bp.route('/api/stats')
@login_required
def api_tasks_stats():
    """API pour les statistiques des tâches"""
    try:
        task_manager = TaskManager(current_app.db)
        stats = task_manager.get_statistics()
        
        return {
            'success': True,
            'stats': stats
        }
        
    except Exception as e:
        logger.error(f"Erreur stats tâches: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500



@tasks_bp.route('/api/cleanup', methods=['POST'])
@admin_required
def api_cleanup_tasks():
    """API pour nettoyer les anciennes tâches (admin seulement)"""
    try:
        # Récupérer les données JSON
        data = request.get_json() if request.is_json else {}
        
        # Valeur par défaut si pas de JSON ou pas de paramètre days
        days = 30  # Par défaut
        
        if data and 'days' in data:
            days = data['days']
        
        # Validation du paramètre days
        if not isinstance(days, (int, float)):
            return {
                'success': False,
                'error': 'Le paramètre "days" doit être un nombre'
            }, 400
        
        # Convertir en entier
        days = int(days)
        
        # Validation de la plage
        if days < 0:
            return {
                'success': False,
                'error': 'Le nombre de jours ne peut pas être négatif'
            }, 400
        
        if days > 365:
            return {
                'success': False,
                'error': 'Le nombre de jours ne peut pas dépasser 365'
            }, 400
        
        # Effectuer le nettoyage
        if days == 0:
            # Cas spécial : supprimer toutes les tâches terminées
            cleaned_count = current_app.db.cleanup_all_completed_tasks()
            message = f'Toutes les tâches terminées ont été supprimées ({cleaned_count} tâches)'
        else:
            # Supprimer les tâches plus anciennes que X jours
            cleaned_count = current_app.db.cleanup_old_tasks(days)
            message = f'Tâches de plus de {days} jour(s) supprimées ({cleaned_count} tâches)'
        
        logger.info(f"Nettoyage tâches: {cleaned_count} tâches supprimées (>{days} jours)")
        
        return {
            'success': True,
            'message': message,
            'cleaned_count': cleaned_count,
            'days': days
        }
        
    except Exception as e:
        logger.error(f"Erreur nettoyage tâches: {e}")
        return {
            'success': False,
            'error': f'Erreur interne: {str(e)}'
        }, 500


@tasks_bp.route('/api/real-stats')
@login_required
def api_real_stats():
    """API pour les vraies statistiques en temps réel"""
    try:
        task_manager = TaskManager(current_app.db)
        
        # Statistiques Celery + Base de données
        celery_stats = task_manager.get_statistics()
        
        # Statistiques base de données
        db_stats = current_app.db.get_stats()
        
        return {
            'success': True,
            'stats': {
                'active': celery_stats['celery']['active'],
                'scheduled': celery_stats['celery']['scheduled'], 
                'completed': db_stats.get('tasks', {}).get('completed', 0),
                'failed': db_stats.get('tasks', {}).get('failed', 0),
                'workers': celery_stats['celery']['workers']
            }
        }
        
    except Exception as e:
        logger.error(f"Erreur stats temps réel: {e}")
        return {
            'success': False,
            'error': str(e),
            'stats': {
                'active': 0,
                'scheduled': 0,
                'completed': 0,
                'failed': 0,
                'workers': 0
            }
        }, 500

@tasks_bp.route('/api/task/<task_id>/hide-from-history', methods=['POST'])
@login_required
def api_hide_task_from_history(task_id):
    """API pour masquer une tâche de l'historique (utilisée par le JavaScript)"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Vérifier les droits d'accès
        task_manager = TaskManager(current_app.db)
        if not task_manager.can_user_access_task(task_id, user_id, user_role):
            return {
                'success': False,
                'error': 'Accès refusé'
            }, 403
        
        # Masquer la tâche
        success = current_app.db.hide_task(task_id)
        
        if success:
            return {
                'success': True,
                'message': 'Tâche masquée de l\'historique'
            }
        else:
            return {
                'success': False,
                'error': 'Tâche non trouvée'
            }, 404
            
    except Exception as e:
        logger.error(f"Erreur masquage tâche {task_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


# ===== TESTING =====

@tasks_bp.route('/test')
@login_required
def test_task_page():
    """Page de test des tâches Celery"""
    return render_template('tasks/test.html')

@tasks_bp.route('/api/test', methods=['POST'])
@login_required
def api_test_task():
    """API pour lancer une tâche de test"""
    try:
        duration = request.json.get('duration', 10)
        
        if not isinstance(duration, int) or duration < 5 or duration > 300:
            return {
                'success': False,
                'error': 'Durée invalide (5-300 secondes)'
            }
        
        task_manager = TaskManager(current_app.db)
        task_id = task_manager.start_test_task(
            duration=duration,
            user_id=session.get('user_id')
        )
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': f'Tâche de test lancée ({duration}s)'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de lancer la tâche de test'
            }
            
    except Exception as e:
        logger.error(f"Erreur tâche test: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500



@tasks_bp.route('/api/download-report/<task_id>')
@login_required
def download_improved_report_api(task_id):
    """API pour télécharger des rapports améliorés - VERSION SIMPLE"""
    try:
        format_type = request.args.get('format', 'both')
        
        task_manager = TaskManager(current_app.db)
        task_status = task_manager.get_task_status(task_id)
        
        if not task_status:
            return jsonify({'success': False, 'error': 'Tâche introuvable'})
        
        # DEBUG ÉTENDU - Voir TOUTE la structure
        logger.info("="*60)
        logger.info(f"🔍 TASK_STATUS KEYS: {list(task_status.keys()) if task_status else 'None'}")
        
        # Extraction plus simple et robuste
        result_data = task_status.get('result', {})
        logger.info(f"🔍 RESULT_DATA TYPE: {type(result_data)}")
        logger.info(f"🔍 RESULT_DATA KEYS: {list(result_data.keys()) if isinstance(result_data, dict) else str(result_data)[:200]}")
        
        # APPROCHE SIMPLE : Créer un rapport même avec données minimales
        hosts_found = []
        services = []
        vulnerabilities = []
        
        # SI C'EST UN DICT, ESSAYER D'EXTRAIRE
        if isinstance(result_data, dict):
            # Ping scan
            ping_data = result_data.get('ping_scan', {})
            if isinstance(ping_data, dict) and ping_data.get('parsed', {}).get('hosts_found'):
                hosts_found = ping_data['parsed']['hosts_found']
                logger.info(f"✅ Hosts depuis ping_scan: {len(hosts_found)}")
            
            # Port scans
            port_scans = result_data.get('port_scans', [])
            logger.info(f"🔍 Port scans trouvés: {len(port_scans)}")
            
            for i, scan in enumerate(port_scans):
                host = scan.get('host', f'host-{i}')
                logger.info(f"🖥️ Scan {i}: host={host}")
                
                # Chercher les ports dans TOUTES les structures possibles
                open_ports = []
                
                # Structure 1: scan['ports']['parsed']['open_ports']
                if scan.get('ports', {}).get('parsed', {}).get('open_ports'):
                    open_ports = scan['ports']['parsed']['open_ports']
                    logger.info(f"📂 Structure 1: {len(open_ports)} ports")
                
                # Structure 2: scan['parsed']['open_ports']
                elif scan.get('parsed', {}).get('open_ports'):
                    open_ports = scan['parsed']['open_ports']
                    logger.info(f"📂 Structure 2: {len(open_ports)} ports")
                
                # Structure 3: scan['open_ports']
                elif scan.get('open_ports'):
                    open_ports = scan['open_ports']
                    logger.info(f"📂 Structure 3: {len(open_ports)} ports")
                
                # Ajouter les services
                for port in open_ports:
                    service = {
                        'name': port.get('service', 'unknown'),
                        'port': port.get('port', 'N/A'),
                        'state': port.get('state', 'open'),
                        'host': host,
                        'protocol': port.get('protocol', 'tcp'),
                        'version': port.get('version', 'Non identifiée')
                    }
                    services.append(service)
                    logger.info(f"➕ Service: {service['name']} sur {service['port']}")
        
        # SI PAS D'HÔTES MAIS DES SERVICES, CRÉER L'HÔTE
        if not hosts_found and services:
            unique_hosts = set(s['host'] for s in services)
            for host_ip in unique_hosts:
                host_services = [s for s in services if s['host'] == host_ip]
                hosts_found.append({
                    'host': host_ip,
                    'ip': host_ip,
                    'status': 'up',
                    'hostname': '',
                    'os': 'Non identifié',
                    'open_ports': [f"{s['port']}/{s['protocol']}" for s in host_services]
                })
                logger.info(f"🖥️ Hôte créé: {host_ip} avec {len(host_services)} services")
        
        # Vulnérabilités selon services
        vuln_map = {
            'ftp': ('FTP détecté', 'Medium', 'Test accès anonyme'),
            'ssh': ('SSH ouvert', 'Info', 'Vérifier config'),
            'telnet': ('Telnet non sécurisé', 'High', 'Texte clair'),
            'http': ('Service web', 'Medium', 'Audit web requis'),
            'mysql': ('MySQL détecté', 'High', 'Test credentials'),
            'smtp': ('SMTP ouvert', 'Medium', 'Vérifier config'),
            'exec': ('Service EXEC', 'Critical', 'Service dangereux'),
            'shell': ('Shell service', 'Critical', 'Accès shell'),
            'login': ('Login service', 'High', 'Auth exposée')
        }
        
        for service in services:
            name = service['name'].lower()
            for pattern, (title, sev, desc) in vuln_map.items():
                if pattern in name:
                    vulnerabilities.append({
                        'title': title,
                        'severity': sev,
                        'cve': 'N/A',
                        'port': service['port'],
                        'description': desc
                    })
        
        # DONNÉES POUR LE RAPPORT
        task_data = {
            'task_id': task_id,
            'target': task_status.get('target', 'N/A'),
            'scan_type': task_status.get('task_type', 'Découverte réseau'),
            'duration': '< 1 minute',
            'hosts_found': hosts_found,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'raw_output': _extract_raw_simple(result_data)
        }
        
        # LOG FINAL
        logger.info(f"📊 RAPPORT FINAL:")
        logger.info(f"  - Hôtes: {len(hosts_found)}")
        logger.info(f"  - Services: {len(services)}")
        logger.info(f"  - Vulnérabilités: {len(vulnerabilities)}")
        logger.info("="*60)
        
        # GÉNÉRER RAPPORT
        exporter = ImprovedReportExporter()
        reports = exporter.generate_discovery_report(task_data, format_type)
        
        return jsonify({
            'success': True,
            **reports
        })
        
    except Exception as e:
        logger.error(f"❌ Erreur rapport: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})


def _extract_raw_simple(result_data):
    """Extraction simple de raw output"""
    if not isinstance(result_data, dict):
        return 'Données non disponibles'
    
    parts = []
    
    # Ping scan
    ping = result_data.get('ping_scan', {})
    if ping.get('stdout'):
        parts.append("=== PING SCAN ===")
        parts.append(ping['stdout'])
    
    # Port scans
    for i, scan in enumerate(result_data.get('port_scans', [])):
        host = scan.get('host', f'host-{i}')
        parts.append(f"\n=== PORT SCAN - {host} ===")
        
        # Chercher stdout
        if scan.get('ports', {}).get('stdout'):
            parts.append(scan['ports']['stdout'])
        elif scan.get('stdout'):
            parts.append(scan['stdout'])
        else:
            parts.append("Sortie non disponible")
    
    return '\n'.join(parts) if parts else 'Aucune sortie disponible'


# AJOUTER AUSSI cette route pour le téléchargement de PDF
@tasks_bp.route('/api/download-pdf/<filename>')
@login_required
def download_pdf_file(filename):
    """Télécharger un fichier PDF généré"""
    try:
        filepath = f"/tmp/{filename}"
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'Fichier introuvable'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

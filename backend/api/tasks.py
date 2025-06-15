from flask import Blueprint, request, render_template, session, current_app, jsonify
from auth import login_required, admin_required
from services.task_manager import TaskManager
from flask import send_file
from .report_exporter import ImprovedReportExporter
import os
import logging
import json
import psycopg2.extras

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
        
        # AJOUTER CETTE LIGNE ⬇️
        current_user = current_app.auth.get_current_user()
        
        return render_template('tasks/dashboard.html', 
                             tasks=tasks, 
                             current_user=current_user)  # ← AJOUTER current_user
        
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
            }, 400
            
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
        user_role = session.get('role', 'user')
        
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
    """API pour télécharger des rapports améliorés - VERSION COMPLÈTE"""
    try:
        format_type = request.args.get('format', 'both')
        logger.info(f"🔄 Génération rapport pour tâche {task_id}, format: {format_type}")
        
        # Vérifier les droits d'accès
        user_id = session.get('user_id')
        user_role = session.get('role', 'user')
        
        task_manager = TaskManager(current_app.db)
        if not task_manager.can_user_access_task(task_id, user_id, user_role):
            return jsonify({'success': False, 'error': 'Accès refusé'}), 403
        
        task_status = task_manager.get_task_status(task_id)
        
        if not task_status:
            return jsonify({'success': False, 'error': 'Tâche non trouvée'}), 404
        
        # Récupérer les données
        result_data = task_status.get('result', {})
        
        # Sécurité : vérifier que result_data est bien un dict
        if not isinstance(result_data, dict):
            logger.warning(f"⚠️ result_data n'est pas un dict: {type(result_data)}")
            result_data = {}
        
        # Debug: afficher la structure principale
        logger.info(f"🔍 result_data keys: {list(result_data.keys()) if result_data else 'empty'}")
        
        # === VARIABLES POUR STOCKER LES DONNÉES ===
        hosts_found = []
        services = []
        vulnerabilities = []
        
        # === PARSING SPÉCIFIQUE SELON LE TYPE DE TÂCHE ===
        task_type = task_status.get('task_type', '')
        
        if 'huntkit_discovery' in task_type:
            hosts_found, services, vulnerabilities = parse_huntkit_discovery(result_data, logger)
        elif 'web_audit' in task_type or 'audit_web' in task_type:
            hosts_found, services, vulnerabilities = parse_web_audit(result_data, logger)
        elif 'forensic' in task_type or 'forensique' in task_type:
            hosts_found, services, vulnerabilities = parse_forensic_analysis(result_data, logger)
        elif 'brute_force' in task_type or 'force_brute' in task_type:
            hosts_found, services, vulnerabilities = parse_brute_force(result_data, logger)
        else:
            # Parsing générique
            hosts_found, services, vulnerabilities = parse_generic_results(result_data, logger)
        
        # Log final des données extraites
        logger.info(f"🎯 DONNÉES FINALES EXTRAITES:")
        logger.info(f"  - Hôtes trouvés: {len(hosts_found)}")
        logger.info(f"  - Services: {len(services)}")
        logger.info(f"  - Vulnérabilités: {len(vulnerabilities)}")
        for i, host in enumerate(hosts_found):
            logger.info(f"    Host {i}: {host['ip']} - {len(host.get('open_ports', []))} ports")
        
        # Préparer les données pour le rapport
        task_data = {
            'task_id': task_id,
            'target': task_status.get('target', 'N/A'),
            'scan_type': task_status.get('task_type', 'Découverte réseau'),
            'duration': '< 1 minute',
            'hosts_found': hosts_found,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'raw_output': _extract_raw_structured(result_data)
        }
        
        # LOG FINAL
        logger.info(f"📊 RAPPORT FINAL:")
        logger.info(f"  - Hôtes: {len(hosts_found)}")
        logger.info(f"  - Services: {len(services)}")
        logger.info(f"  - Vulnérabilités: {len(vulnerabilities)}")
        logger.info("="*60)
        
        # GÉNÉRER RAPPORT
        from .report_exporter import ImprovedReportExporter
        exporter = ImprovedReportExporter()
        reports = exporter.generate_discovery_report(task_data, format_type)
        
        logger.info(f"✅ Rapports générés avec succès pour tâche {task_id}")
        
        return jsonify({
            'success': True,
            **reports
        })
        
    except Exception as e:
        logger.error(f"❌ Erreur rapport: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500


# AJOUTER AUSSI cette route pour le téléchargement de PDF
@tasks_bp.route('/api/download-pdf/<filename>')
@login_required
def download_pdf_file(filename):
    """Télécharger un fichier PDF généré - VERSION CORRIGÉE"""
    try:
        # Sécurité : vérifier le nom de fichier
        from werkzeug.utils import secure_filename
        safe_filename = secure_filename(filename)
        
        # Chercher le fichier dans plusieurs emplacements possibles
        possible_paths = [
            f"/tmp/{safe_filename}",
            f"/app/tmp/{safe_filename}",
            f"./tmp/{safe_filename}",
            f"/var/tmp/{safe_filename}"
        ]
        
        filepath = None
        for path in possible_paths:
            if os.path.exists(path):
                filepath = path
                logger.info(f"✅ PDF trouvé: {filepath}")
                break
        
        if not filepath:
            logger.error(f"❌ PDF introuvable: {safe_filename}")
            logger.error(f"🔍 Chemins testés: {possible_paths}")
            
            # Lister le contenu de /tmp pour debug
            try:
                tmp_files = os.listdir("/tmp")
                logger.error(f"📁 Fichiers dans /tmp: {tmp_files}")
            except:
                pass
                
            return jsonify({
                'error': 'Fichier PDF introuvable', 
                'filename': safe_filename,
                'message': 'Le fichier a peut-être expiré ou été supprimé'
            }), 404
        
        # Vérifier que c'est bien un PDF
        if not safe_filename.lower().endswith('.pdf'):
            return jsonify({'error': 'Type de fichier non autorisé'}), 400
        
        # Télécharger le fichier
        logger.info(f"📄 Téléchargement PDF: {filepath}")
        return send_file(
            filepath, 
            as_attachment=True, 
            download_name=safe_filename,
            mimetype='application/pdf'
        )
        
    except FileNotFoundError:
        logger.error(f"❌ Fichier non trouvé: {filename}")
        return jsonify({'error': 'Fichier introuvable'}), 404
    except PermissionError:
        logger.error(f"❌ Permission refusée: {filename}")
        return jsonify({'error': 'Accès refusé au fichier'}), 403
    except Exception as e:
        logger.error(f"❌ Erreur téléchargement PDF: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

# ===== FONCTIONS DE PARSING SPÉCIALISÉES =====

def parse_huntkit_discovery(result_data, logger):
    """Parse les résultats de découverte huntkit"""
    hosts_found = []
    services = []
    vulnerabilities = []
    
    logger.info("🌐 Parsing huntkit discovery")
    
    if isinstance(result_data, dict):
        target = result_data.get('target', 'unknown')
        
        # Afficher le contenu pour debug
        if 'results' in result_data:
            results = result_data['results']
            logger.info(f"🔍 results type: {type(results)}")
            if isinstance(results, dict):
                logger.info(f"🔍 results keys: {list(results.keys())}")
                    
        if 'summary' in result_data:
            summary = result_data['summary']
            logger.info(f"🔍 summary: {summary}")
        
        # MÉTHODE 1: Parser le summary qui dit "1 hôtes trouvés"
        summary = result_data.get('summary', '')
        
        if isinstance(summary, str) and 'hôtes trouvés' in summary:
            logger.info(f"✅ Summary indique des hôtes: {summary}")
            
            # Parser "Découverte terminée: 1 hôtes trouvés en 0s"
            import re
            match = re.search(r'(\d+)\s+hôtes?\s+trouvés?', summary)
            if match:
                nb_hosts = int(match.group(1))
                logger.info(f"✅ {nb_hosts} hôtes détectés dans le summary")
                
                # Créer un hôte basique depuis la target
                if target and target != 'unknown':
                    hosts_found.append({
                        'ip': target,
                        'address': target,
                        'status': 'up',
                        'hostname': '',
                        'os': 'Détecté par huntkit',
                        'open_ports': []
                    })
                    logger.info(f"✅ Hôte créé depuis target: {target}")
        
        # MÉTHODE 2: Chercher dans la structure 'results'
        results = result_data.get('results', {})
        if isinstance(results, dict):
            logger.info(f"✅ Analyse de la structure results")
            
            # Chercher ping_scan et port_scans dans results
            ping_data = results.get('ping_scan', {})
            port_scans = results.get('port_scans', [])
            
            logger.info(f"🔍 ping_data trouvé: {bool(ping_data)}")
            logger.info(f"🔍 port_scans trouvé: {len(port_scans) if isinstance(port_scans, list) else 0}")
            
            # Parser ping_scan si disponible
            if isinstance(ping_data, dict) and 'parsed' in ping_data:
                parsed_ping = ping_data['parsed']
                if isinstance(parsed_ping, dict) and 'hosts_found' in parsed_ping:
                    raw_hosts = parsed_ping['hosts_found']
                    logger.info(f"✅ Trouvé {len(raw_hosts)} hôtes dans results.ping_scan.parsed.hosts_found")
                    
                    for host_data in raw_hosts:
                        if isinstance(host_data, dict):
                            hosts_found.append({
                                'ip': host_data.get('host', 'unknown'),
                                'address': host_data.get('host', 'unknown'),
                                'status': host_data.get('status', 'up'),
                                'hostname': '',
                                'os': '',
                                'open_ports': []
                            })
            
            # Parser port_scans si disponible
            if isinstance(port_scans, list) and port_scans:
                logger.info(f"✅ Parsing {len(port_scans)} port scans")
                
                for i, scan in enumerate(port_scans):
                    if isinstance(scan, dict):
                        host_ip = scan.get('host', f'host-{i}')
                        logger.info(f"🔍 Port scan {i}: host={host_ip}")
                        
                        # Extraire les ports
                        open_ports = []
                        ports_data = scan.get('ports', {})
                        
                        if isinstance(ports_data, dict):
                            # Méthode 1: ports.parsed.open_ports
                            parsed_ports = ports_data.get('parsed', {})
                            if isinstance(parsed_ports, dict) and 'open_ports' in parsed_ports:
                                open_ports = parsed_ports['open_ports']
                                logger.info(f"    ✅ Trouvé {len(open_ports)} ports dans structure parsée")
                            
                            # Méthode 2: Parser stdout
                            elif 'stdout' in ports_data:
                                stdout = ports_data['stdout']
                                logger.info(f"    ✅ Parsing stdout ports ({len(stdout)} chars)")
                                
                                import re
                                port_pattern = r'(\d+)\/tcp\s+open\s+([^\s\n]+)'
                                matches = re.findall(port_pattern, stdout)
                                
                                for port, service in matches:
                                    open_ports.append({
                                        'port': port,
                                        'protocol': 'tcp',
                                        'state': 'open',
                                        'service': service.strip()
                                    })
                                
                                logger.info(f"    ✅ Parsed {len(open_ports)} ports depuis stdout")
                        
                        # Mettre à jour l'hôte existant ou créer un nouveau
                        host_updated = False
                        for host in hosts_found:
                            if host['ip'] == host_ip or host['address'] == host_ip:
                                if isinstance(open_ports, list) and open_ports:
                                    host['open_ports'] = []
                                    for p in open_ports:
                                        if isinstance(p, dict):
                                            host['open_ports'].append(p.get('port', 'unknown'))
                                        else:
                                            host['open_ports'].append(str(p))
                                host_updated = True
                                break
                        
                        # Créer un nouvel hôte si pas trouvé
                        if not host_updated and host_ip != 'unknown':
                            new_host = {
                                'ip': host_ip,
                                'address': host_ip,
                                'status': 'up',
                                'hostname': '',
                                'os': '',
                                'open_ports': []
                            }
                            if isinstance(open_ports, list) and open_ports:
                                for p in open_ports:
                                    if isinstance(p, dict):
                                        new_host['open_ports'].append(p.get('port', 'unknown'))
                                    else:
                                        new_host['open_ports'].append(str(p))
                            hosts_found.append(new_host)
                            logger.info(f"✅ Créé nouvel hôte: {host_ip}")
                        
                        # Créer des services
                        for port_info in open_ports:
                            if isinstance(port_info, dict):
                                service_name = port_info.get('service', f"tcp/{port_info.get('port', 'unknown')}")
                                services.append({
                                    'name': service_name,
                                    'port': port_info.get('port', 'unknown'),
                                    'protocol': port_info.get('protocol', 'tcp'),
                                    'state': port_info.get('state', 'open'),
                                    'version': '',
                                    'host': host_ip
                                })
                                
                                # Ajouter vulnérabilités
                                port_num = port_info.get('port', '')
                                if port_num == '22':
                                    vulnerabilities.append({
                                        'title': 'Service SSH détecté',
                                        'severity': 'Info',
                                        'cve': '',
                                        'port': port_num,
                                        'description': 'Service SSH actif - vérifier la configuration',
                                        'host': host_ip
                                    })
                                elif port_num == '21':
                                    vulnerabilities.append({
                                        'title': 'Service FTP détecté',
                                        'severity': 'Medium',
                                        'cve': '',
                                        'port': port_num,
                                        'description': 'Service FTP détecté - vérifier la configuration sécurisée',
                                        'host': host_ip
                                    })
        
        # MÉTHODE 3: Si toujours rien, créer au moins un hôte depuis target
        if not hosts_found and target and target != 'unknown':
            logger.info(f"✅ Création hôte minimal depuis target: {target}")
            hosts_found.append({
                'ip': target,
                'address': target,
                'status': 'detected',
                'hostname': '',
                'os': 'Système détecté',
                'open_ports': []
            })
    
    logger.info(f"🌐 Huntkit discovery parsed: {len(hosts_found)} hôtes, {len(services)} services, {len(vulnerabilities)} vulnérabilités")
    return hosts_found, services, vulnerabilities


def parse_web_audit(result_data, logger):
    """Parse les résultats d'audit web (Nikto + Nuclei + SQLMap)"""
    hosts_found = []
    services = []
    vulnerabilities = []
    
    logger.info("🕷️ Parsing audit web")
    
    if isinstance(result_data, dict):
        target = result_data.get('target', 'unknown')
        
        # Créer un hôte de base
        if target and target != 'unknown':
            hosts_found.append({
                'ip': target,
                'address': target,
                'status': 'audited',
                'hostname': '',
                'os': 'Serveur Web',
                'open_ports': ['80', '443']  # Ports web standard
            })
        
        # Analyser la structure results
        results = result_data.get('results', {})
        if isinstance(results, dict):
            logger.info(f"🔍 Audit web - results keys: {list(results.keys())}")
            
            # === PARSER NIKTO ===
            nikto_data = results.get('nikto', {})
            if isinstance(nikto_data, dict):
                nikto_parsed = nikto_data.get('parsed', {})
                if isinstance(nikto_parsed, dict):
                    nikto_vulns = nikto_parsed.get('vulnerabilities', [])
                    total_nikto = nikto_parsed.get('total_vulnerabilities', len(nikto_vulns))
                    
                    logger.info(f"🕷️ Nikto: {total_nikto} vulnérabilités trouvées")
                    
                    for i, vuln in enumerate(nikto_vulns):
                        vulnerabilities.append({
                            'title': f'Nikto - {vuln[:50]}...' if len(vuln) > 50 else f'Nikto - {vuln}',
                            'severity': 'Medium',
                            'cve': '',
                            'port': '80',
                            'description': vuln,
                            'host': target,
                            'source': 'Nikto'
                        })
            
            # === PARSER NUCLEI ===
            nuclei_data = results.get('nuclei', {})
            if isinstance(nuclei_data, dict):
                nuclei_parsed = nuclei_data.get('parsed', {})
                if isinstance(nuclei_parsed, dict):
                    nuclei_vulns = nuclei_parsed.get('vulnerabilities', [])
                    total_nuclei = nuclei_parsed.get('total_vulnerabilities', len(nuclei_vulns))
                    
                    logger.info(f"🎯 Nuclei: {total_nuclei} vulnérabilités trouvées")
                    
                    for vuln in nuclei_vulns:
                        if isinstance(vuln, dict):
                            # Structure Nuclei JSON
                            template_id = vuln.get('template-id', 'unknown')
                            info = vuln.get('info', {})
                            severity = info.get('severity', 'medium')
                            name = info.get('name', template_id)
                            
                            vulnerabilities.append({
                                'title': f'Nuclei - {name}',
                                'severity': severity.capitalize(),
                                'cve': '',
                                'port': '80',
                                'description': f'Template: {template_id}',
                                'host': target,
                                'source': 'Nuclei'
                            })
                        elif isinstance(vuln, str):
                            # Structure string simple
                            vulnerabilities.append({
                                'title': f'Nuclei - {vuln[:50]}...' if len(vuln) > 50 else f'Nuclei - {vuln}',
                                'severity': 'Medium',
                                'cve': '',
                                'port': '80',
                                'description': vuln,
                                'host': target,
                                'source': 'Nuclei'
                            })
            
            # === PARSER SQLMAP ===
            sqlmap_data = results.get('sqlmap', {})
            if isinstance(sqlmap_data, dict):
                sqlmap_parsed = sqlmap_data.get('parsed', {})
                if isinstance(sqlmap_parsed, dict):
                    sql_vulnerable = sqlmap_parsed.get('vulnerable', False)
                    injection_points = sqlmap_parsed.get('injection_points', [])
                    
                    logger.info(f"💉 SQLMap: Vulnérable = {sql_vulnerable}")
                    
                    if sql_vulnerable:
                        vulnerabilities.append({
                            'title': 'Injection SQL détectée',
                            'severity': 'Critical',
                            'cve': '',
                            'port': '80',
                            'description': f'Points d\'injection trouvés: {len(injection_points)}',
                            'host': target,
                            'source': 'SQLMap'
                        })
        
        # Créer des services web
        services.extend([
            {
                'name': 'HTTP',
                'port': '80',
                'protocol': 'tcp',
                'state': 'open',
                'version': 'Serveur Web détecté',
                'host': target
            },
            {
                'name': 'HTTPS',
                'port': '443',
                'protocol': 'tcp',
                'state': 'assumed',
                'version': 'SSL/TLS',
                'host': target
            }
        ])
    
    logger.info(f"🕷️ Audit web parsed: {len(vulnerabilities)} vulnérabilités trouvées")
    return hosts_found, services, vulnerabilities


def parse_forensic_analysis(result_data, logger):
    """Parse les résultats d'analyse forensique (Wireshark + Volatility)"""
    hosts_found = []
    services = []
    vulnerabilities = []
    
    logger.info("🔍 Parsing analyse forensique")
    
    if isinstance(result_data, dict):
        target = result_data.get('target', result_data.get('pcap_file', 'forensic_analysis'))
        
        # Créer un "hôte" pour l'analyse forensique
        hosts_found.append({
            'ip': 'Analyse Forensique',
            'address': target,
            'status': 'analyzed',
            'hostname': '',
            'os': 'Artefacts numériques',
            'open_ports': []
        })
        
        # Analyser la structure results
        results = result_data.get('results', {})
        if isinstance(results, dict):
            logger.info(f"🔍 Forensique - results keys: {list(results.keys())}")
            
            # === PARSER WIRESHARK ===
            wireshark_data = results.get('wireshark', {}) or results.get('pcap_analysis', {})
            if isinstance(wireshark_data, dict):
                # Statistiques réseau
                general_info = wireshark_data.get('general_info', {})
                protocols = wireshark_data.get('protocols', [])
                conversations = wireshark_data.get('conversations', [])
                
                logger.info(f"🌐 Wireshark: {len(protocols)} protocoles, {len(conversations)} conversations")
                
                # Créer des "services" depuis les protocoles
                for protocol in protocols[:10]:  # Top 10
                    if isinstance(protocol, dict):
                        proto_name = protocol.get('protocol', 'unknown')
                        frames = protocol.get('frames', '0')
                        
                        services.append({
                            'name': f'Protocole {proto_name.upper()}',
                            'port': 'N/A',
                            'protocol': 'network',
                            'state': 'detected',
                            'version': f'{frames} frames',
                            'host': 'Analyse réseau'
                        })
                
                # Détecter des anomalies potentielles
                if len(protocols) > 20:
                    vulnerabilities.append({
                        'title': 'Diversité protocolaire élevée',
                        'severity': 'Info',
                        'cve': '',
                        'port': 'N/A',
                        'description': f'{len(protocols)} protocoles différents détectés',
                        'host': 'Analyse réseau',
                        'source': 'Wireshark'
                    })
            
            # === PARSER VOLATILITY ===
            volatility_data = results.get('volatility', {}) or results.get('memory_analysis', {})
            if isinstance(volatility_data, dict):
                processes = volatility_data.get('processes', [])
                network_connections = volatility_data.get('network_connections', [])
                
                logger.info(f"🧠 Volatility: {len(processes)} processus, {len(network_connections)} connexions")
                
                # Analyser les processus suspects
                for process in processes[:20]:  # Top 20 processus
                    if isinstance(process, dict):
                        proc_name = process.get('name', 'unknown')
                        pid = process.get('pid', '0')
                        
                        services.append({
                            'name': f'Processus {proc_name}',
                            'port': pid,
                            'protocol': 'memory',
                            'state': 'running',
                            'version': f'PID {pid}',
                            'host': 'Analyse mémoire'
                        })
                
                # Détecter des connexions suspectes
                suspicious_ports = ['4444', '6666', '1337', '31337']
                for conn in network_connections:
                    if isinstance(conn, dict):
                        local_port = str(conn.get('local_port', ''))
                        foreign_addr = conn.get('foreign_addr', '')
                        
                        if local_port in suspicious_ports:
                            vulnerabilities.append({
                                'title': f'Port suspect détecté: {local_port}',
                                'severity': 'High',
                                'cve': '',
                                'port': local_port,
                                'description': f'Connexion vers {foreign_addr}',
                                'host': 'Analyse mémoire',
                                'source': 'Volatility'
                            })
            
            # === PARSER CLAMAV ===
            clamav_data = results.get('clamav', {}) or results.get('antivirus', {})
            if isinstance(clamav_data, dict):
                threats_found = clamav_data.get('threats_found', [])
                
                logger.info(f"🦠 ClamAV: {len(threats_found)} menaces détectées")
                
                for threat in threats_found:
                    if isinstance(threat, dict):
                        threat_name = threat.get('name', 'Malware détecté')
                        file_path = threat.get('file', 'unknown')
                        
                        vulnerabilities.append({
                            'title': f'Malware: {threat_name}',
                            'severity': 'Critical',
                            'cve': '',
                            'port': 'N/A',
                            'description': f'Fichier infecté: {file_path}',
                            'host': 'Analyse antivirus',
                            'source': 'ClamAV'
                        })
    
    logger.info(f"🔍 Forensique parsed: {len(vulnerabilities)} anomalies trouvées")
    return hosts_found, services, vulnerabilities


def parse_brute_force(result_data, logger):
    """Parse les résultats de force brute (Hydra)"""
    hosts_found = []
    services = []
    vulnerabilities = []
    
    logger.info("🔨 Parsing force brute")
    
    if isinstance(result_data, dict):
        target = result_data.get('target', 'unknown')
        service_type = result_data.get('service', 'ssh')
        
        # Créer un hôte de base
        if target and target != 'unknown':
            hosts_found.append({
                'ip': target,
                'address': target,
                'status': 'tested',
                'hostname': '',
                'os': 'Système testé',
                'open_ports': ['22'] if service_type == 'ssh' else ['21']
            })
        
        # Analyser les credentials trouvés
        credentials_found = result_data.get('credentials_found', [])
        results = result_data.get('results', {})
        
        logger.info(f"🔨 Force brute: {len(credentials_found)} credentials trouvés")
        
        # Parser depuis results.parsed si disponible
        if isinstance(results, dict) and 'parsed' in results:
            parsed = results['parsed']
            if isinstance(parsed, dict):
                credentials_found.extend(parsed.get('credentials_found', []))
        
        # Créer des vulnérabilités pour chaque credential
        for cred in credentials_found:
            if isinstance(cred, dict):
                username = cred.get('username', 'unknown')
                password = cred.get('password', 'unknown')
                
                vulnerabilities.append({
                    'title': f'Credentials faibles: {username}',
                    'severity': 'Critical',
                    'cve': '',
                    'port': '22' if service_type == 'ssh' else '21',
                    'description': f'Mot de passe faible découvert: {username}:{password}',
                    'host': target,
                    'source': 'Hydra'
                })
        
        # Créer le service testé
        port = '22' if service_type == 'ssh' else '21'
        services.append({
            'name': service_type.upper(),
            'port': port,
            'protocol': 'tcp',
            'state': 'vulnerable' if credentials_found else 'tested',
            'version': 'Testé par force brute',
            'host': target
        })
        
        # Si aucun credential trouvé, c'est une bonne nouvelle
        if not credentials_found:
            vulnerabilities.append({
                'title': f'Service {service_type.upper()} résistant',
                'severity': 'Info',
                'cve': '',
                'port': port,
                'description': 'Aucun credential faible détecté',
                'host': target,
                'source': 'Hydra'
            })
    
    logger.info(f"🔨 Force brute parsed: {len(credentials_found)} credentials, {len(vulnerabilities)} vulnérabilités")
    return hosts_found, services, vulnerabilities


def parse_generic_results(result_data, logger):
    """Parse générique pour autres types de résultats"""
    hosts_found = []
    services = []
    vulnerabilities = []
    
    logger.info("📋 Parsing générique")
    
    if isinstance(result_data, dict):
        target = result_data.get('target', 'unknown')
        
        if target and target != 'unknown':
            hosts_found.append({
                'ip': target,
                'address': target,
                'status': 'analyzed',
                'hostname': '',
                'os': 'Système analysé',
                'open_ports': []
            })
        
        # Chercher des résultats dans différentes structures
        success = result_data.get('success', True)
        if not success:
            vulnerabilities.append({
                'title': 'Échec de l\'analyse',
                'severity': 'Medium',
                'cve': '',
                'port': 'N/A',
                'description': result_data.get('error', 'Erreur inconnue'),
                'host': target,
                'source': 'Analyse générique'
            })
    
    return hosts_found, services, vulnerabilities


def _extract_raw_structured(result_data):
    """Extraction raw output bien structurée et lisible"""
    if not isinstance(result_data, dict):
        return f'Données non disponibles (type: {type(result_data)})'
    
    parts = []
    
    # === PING SCAN ===
    results = result_data.get('results', {})
    if isinstance(results, dict):
        ping = results.get('ping_scan', {})
        if isinstance(ping, dict) and ping.get('stdout'):
            parts.append("=" * 50)
            parts.append("DÉCOUVERTE D'HÔTES (PING SCAN)")
            parts.append("=" * 50)
            parts.append(ping['stdout'])
            parts.append("")
        
        # === PORT SCANS ===
        port_scans = results.get('port_scans', [])
        for i, scan in enumerate(port_scans):
            if isinstance(scan, dict):
                host = scan.get('host', f'host-{i}')
                parts.append("=" * 50)
                parts.append(f"SCAN DE PORTS - {host}")
                parts.append("=" * 50)
                
                ports_data = scan.get('ports', {})
                if isinstance(ports_data, dict) and ports_data.get('stdout'):
                    parts.append(ports_data['stdout'])
                    parts.append("")
        
        # === AUDIT WEB ===
        nikto_data = results.get('nikto', {})
        if isinstance(nikto_data, dict) and nikto_data.get('stdout'):
            parts.append("=" * 50)
            parts.append("AUDIT WEB - NIKTO")
            parts.append("=" * 50)
            parts.append(nikto_data['stdout'])
            parts.append("")
        
        nuclei_data = results.get('nuclei', {})
        if isinstance(nuclei_data, dict) and nuclei_data.get('stdout'):
            parts.append("=" * 50)
            parts.append("AUDIT WEB - NUCLEI")
            parts.append("=" * 50)
            parts.append(nuclei_data['stdout'])
            parts.append("")
        
        # === FORCE BRUTE ===
        if 'credentials_found' in result_data:
            parts.append("=" * 50)
            parts.append("FORCE BRUTE - HYDRA")
            parts.append("=" * 50)
            creds = result_data.get('credentials_found', [])
            if creds:
                parts.append(f"Credentials trouvés: {len(creds)}")
                for cred in creds[:5]:  # Premiers 5
                    if isinstance(cred, dict):
                        parts.append(f"  - {cred.get('username', 'N/A')}:{cred.get('password', 'N/A')}")
            else:
                parts.append("Aucun credential faible détecté")
            parts.append("")
    
    # === RÉSUMÉ ===
    if 'summary' in result_data:
        parts.append("=" * 50)
        parts.append("RÉSUMÉ DE L'ANALYSE")
        parts.append("=" * 50)
        summary = result_data['summary']
        if isinstance(summary, dict):
            for key, value in summary.items():
                parts.append(f"{key}: {value}")
        else:
            parts.append(str(summary))
        parts.append("")
    
    return '\n'.join(parts) if parts else 'Aucune sortie disponible'


@tasks_bp.route('/api/<task_id>/assign', methods=['POST'])
@login_required
def api_assign_task(task_id):
    """API pour attribuer une tâche à un invité"""
    try:
        user_role = session.get('role')
        user_id = session.get('user_id')
        
        # Vérifier les permissions (admin ou pentester)
        if user_role not in ['admin', 'pentester']:
            return {
                'success': False,
                'error': 'Droits insuffisants'
            }, 403
        
        data = request.get_json()
        guest_id = data.get('guest_id')
        message = data.get('message', '')
        
        if not guest_id:
            return {
                'success': False,
                'error': 'ID invité manquant'
            }, 400
        
        # Vérifier que la tâche existe et appartient à l'utilisateur
        task_manager = TaskManager(current_app.db)
        if not task_manager.can_user_access_task(task_id, user_id, user_role):
            return {
                'success': False,
                'error': 'Tâche non accessible'
            }, 403
        
        # Vérifier que le destinataire est bien un invité
        guest_user = current_app.db.get_user_by_id(guest_id)
        if not guest_user or guest_user.get('role') != 'viewer':
            return {
                'success': False,
                'error': 'Utilisateur invité invalide'
            }, 400
        
        # Attribuer la tâche
        success = current_app.db.assign_task_to_user(task_id, guest_id, user_id, message)
        
        if success:
            return {
                'success': True,
                'message': f'Tâche attribuée à {guest_user.get("username")}'
            }
        else:
            return {
                'success': False,
                'error': 'Erreur lors de l\'attribution'
            }, 500
            
    except Exception as e:
        logger.error(f"Erreur attribution tâche {task_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500



@tasks_bp.route('/api/guests')
@login_required
def api_get_guests():
    """API pour récupérer la liste des invités - VERSION CORRIGÉE"""
    try:
        user_role = session.get('role')
        
        # Vérifier les permissions
        if user_role not in ['admin', 'pentester']:
            return {
                'success': False,
                'error': 'Droits insuffisants'
            }, 403
        
        # ✅ SOLUTION TEMPORAIRE : Utiliser get_users() et filtrer manuellement
        all_users = current_app.db.get_users()
        guests = [user for user in all_users if user.get('role') == 'viewer']
        
        return {
            'success': True,
            'guests': [
                {
                    'id': guest['id'],
                    'username': guest['username'],
                    'last_login': guest.get('last_login')
                }
                for guest in guests
            ]
        }
        
    except Exception as e:
        logger.error(f"Erreur récupération invités: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@tasks_bp.route('/api/real-stats')
@login_required
def api_real_stats():
    """API pour les statistiques en temps réel"""
    try:
        stats = current_app.db.get_stats()
        return {
            'success': True,
            'stats': stats or {}
        }
    except Exception as e:
        logger.error(f"Erreur stats: {e}")
        return {
            'success': False,
            'error': str(e)
        }

@tasks_bp.route('/api/list')
@login_required  
def api_tasks_list():
    """API pour la liste des tâches"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        limit = request.args.get('limit', 20, type=int)
        
        if user_role == 'admin':
            tasks = current_app.db.get_tasks(include_hidden=False, limit=limit)
        else:
            tasks = current_app.db.get_tasks(user_id=user_id, include_hidden=False, limit=limit)
        
        return {
            'success': True,
            'tasks': tasks or []
        }
    except Exception as e:
        logger.error(f"Erreur liste tâches: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@tasks_bp.route('/api/debug-users')
@login_required
def api_debug_users():
    """Route de debug pour voir tous les utilisateurs"""
    try:
        all_users = current_app.db.get_users()
        viewers = current_app.db.get_users_by_role('viewer')
        
        return {
            'success': True,
            'all_users': all_users,
            'viewers_only': viewers,
            'debug_info': {
                'total_users': len(all_users),
                'total_viewers': len(viewers)
            }
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500


@tasks_bp.route('/api/debug-sql')
@login_required
def api_debug_sql():
    """Route de debug SQL pour comprendre le problème - Version simplifiée"""
    try:
        results = {}
        
        # Test 1: Via la méthode get_users
        results['all_users_method'] = current_app.db.get_users()
        
        # Test 2: Via la méthode get_users_by_role
        results['viewers_method'] = current_app.db.get_users_by_role('viewer')
        
        # Test 3: Filtrer manuellement les viewers depuis get_users()
        all_users = current_app.db.get_users()
        manual_viewers = [user for user in all_users if user.get('role') == 'viewer']
        results['viewers_manual_filter'] = manual_viewers
        
        # Test 4: Debug info
        results['debug_info'] = {
            'total_users': len(all_users),
            'viewers_from_method': len(results['viewers_method']),
            'viewers_from_manual': len(manual_viewers),
            'roles_found': list(set(user.get('role') for user in all_users))
        }
        
        return {
            'success': True,
            'debug_results': results
        }
        
    except Exception as e:
        logger.error(f"Erreur debug SQL: {e}")
        return {
            'success': False, 
            'error': str(e)
        }, 500


@tasks_bp.route('/api/cleanup', methods=['POST'])
@login_required
def api_cleanup_tasks():
    """API pour purger les tâches terminées"""
    try:
        user_role = session.get('role')
        
        # Vérifier les permissions (admin seulement)
        if user_role != 'admin':
            return {
                'success': False,
                'error': 'Droits insuffisants - admin requis'
            }, 403
        
        data = request.get_json()
        days = data.get('days', 0)
        
        if days == 0:
            # Purge complète
            count = current_app.db.cleanup_all_completed_tasks()
            message = f"{count} tâches terminées supprimées définitivement"
        else:
            # Masquer les anciennes tâches
            count = current_app.db.cleanup_old_tasks(days)
            message = f"{count} tâches anciennes masquées (>{days} jours)"
        
        return {
            'success': True,
            'message': message,
            'count': count
        }
        
    except Exception as e:
        logger.error(f"Erreur purge tâches: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500


@tasks_bp.route('/api/task/<task_id>/hide-from-history', methods=['POST'])
@login_required
def api_hide_task_from_history(task_id):
    """API pour masquer une tâche spécifique de l'historique"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role', 'user')
        
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


@tasks_bp.route('/api/debug-statuses')
@login_required
def api_debug_statuses():
    """Debug : voir les statuts des tâches"""
    try:
        with current_app.db.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Compter les tâches par statut
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM tasks 
                GROUP BY status
                ORDER BY status
            ''')
            status_counts = [dict(row) for row in cursor.fetchall()]
            
            # Exemples de tâches
            cursor.execute('''
                SELECT task_id, task_name, status, started_at, completed_at
                FROM tasks 
                ORDER BY started_at DESC 
                LIMIT 10
            ''')
            sample_tasks = [dict(row) for row in cursor.fetchall()]
            
            return {
                'success': True,
                'status_counts': status_counts,
                'sample_tasks': sample_tasks
            }
            
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500

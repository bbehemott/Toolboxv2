from flask import Blueprint, request, render_template, session, current_app, jsonify, flash, redirect, url_for
from auth import login_required, pentester_required
from services.scan_orchestrator import ScanOrchestrator
import logging
import time

logger = logging.getLogger('toolbox.scans')

scans_bp = Blueprint('scans', __name__)

# ===== PAGES OPENVAS =====

@scans_bp.route('/openvas', methods=['GET', 'POST'])
@pentester_required
def openvas_page():
    """Page principale OpenVAS"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        scan_name = request.form.get('scan_name', '').strip()
        scan_type = request.form.get('scan_type', 'full_and_fast')
        
        if not target:
            flash('Veuillez indiquer une cible à scanner', 'warning')
            return render_template('scans/openvas.html')
        
        if not scan_name:
            scan_name = f'Scan_{target}_{int(time.time())}'
        
        try:
            # Validation de la cible
            from core.nmap_wrapper import NmapWrapper
            is_valid, validation_msg = NmapWrapper.validate_target(target)
            
            if not is_valid:
                flash(f'Cible invalide: {validation_msg}', 'danger')
                return render_template('scans/openvas.html')
            
            # Lancer le scan OpenVAS
            orchestrator = ScanOrchestrator(current_app.db)
            scan_id = orchestrator.start_openvas_scan(
                target=target,
                scan_name=scan_name,
                scan_type=scan_type,
                user_id=session.get('user_id')
            )
            
            if scan_id:
                flash(f'Scan OpenVAS lancé: {scan_name}', 'success')
                return redirect(url_for('scans.openvas_page'))
            else:
                flash('Erreur lors du lancement du scan OpenVAS', 'danger')
                
        except Exception as e:
            logger.error(f"Erreur scan OpenVAS: {e}")
            flash(f'Erreur: {str(e)}', 'danger')
    
    # Récupérer les scans pour affichage
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Admin voit tous les scans
        if user_role == 'admin':
            active_scans = current_app.db.get_scans(active_only=True, limit=10)
            all_scans = current_app.db.get_scans(limit=20)
        else:
            active_scans = current_app.db.get_scans(user_id=user_id, active_only=True, limit=10)
            all_scans = current_app.db.get_scans(user_id=user_id, limit=20)
        
        return render_template('scans/openvas.html', 
                             active_scans=active_scans,
                             all_scans=all_scans)
                             
    except Exception as e:
        logger.error(f"Erreur récupération scans: {e}")
        return render_template('scans/openvas.html', 
                             active_scans=[], 
                             all_scans=[])

@scans_bp.route('/openvas/<int:scan_id>')
@login_required
def openvas_scan_details(scan_id):
    """Détails d'un scan OpenVAS"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        scan = orchestrator.get_scan_details(scan_id, user_id, user_role)
        
        if not scan:
            flash('Scan non trouvé', 'danger')
            return redirect(url_for('scans.openvas_page'))
        
        return render_template('scans/details.html', scan=scan)
        
    except Exception as e:
        logger.error(f"Erreur détails scan {scan_id}: {e}")
        flash('Erreur lors de la récupération des détails', 'danger')
        return redirect(url_for('scans.openvas_page'))

# ===== API ENDPOINTS =====

@scans_bp.route('/api/openvas/status')
@login_required
def api_openvas_status():
    """API pour récupérer le statut des scans OpenVAS actifs"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        active_scans = orchestrator.get_active_scans_status(user_id, user_role)
        
        return {
            'success': True,
            'scans': active_scans
        }
        
    except Exception as e:
        logger.error(f"Erreur API status OpenVAS: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/<int:scan_id>/pause', methods=['POST'])
@pentester_required
def api_pause_scan(scan_id):
    """API pour mettre en pause un scan"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        success = orchestrator.pause_scan(scan_id, user_id, user_role)
        
        if success:
            return {
                'success': True,
                'message': 'Scan mis en pause'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de mettre en pause le scan'
            }
            
    except Exception as e:
        logger.error(f"Erreur pause scan {scan_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/<int:scan_id>/resume', methods=['POST'])
@pentester_required
def api_resume_scan(scan_id):
    """API pour reprendre un scan en pause"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        success = orchestrator.resume_scan(scan_id, user_id, user_role)
        
        if success:
            return {
                'success': True,
                'message': 'Scan repris'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de reprendre le scan'
            }
            
    except Exception as e:
        logger.error(f"Erreur reprise scan {scan_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/<int:scan_id>/stop', methods=['POST'])
@pentester_required
def api_stop_scan(scan_id):
    """API pour arrêter définitivement un scan"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        success = orchestrator.stop_scan(scan_id, user_id, user_role)
        
        if success:
            return {
                'success': True,
                'message': 'Scan arrêté'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible d\'arrêter le scan'
            }
            
    except Exception as e:
        logger.error(f"Erreur arrêt scan {scan_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/<int:scan_id>/delete', methods=['DELETE'])
@pentester_required
def api_delete_scan(scan_id):
    """API pour supprimer un scan de l'historique"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        success = orchestrator.delete_scan(scan_id, user_id, user_role)
        
        if success:
            return {
                'success': True,
                'message': 'Scan supprimé de l\'historique'
            }
        else:
            return {
                'success': False,
                'error': 'Impossible de supprimer le scan'
            }
            
    except Exception as e:
        logger.error(f"Erreur suppression scan {scan_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/<int:scan_id>/results')
@login_required
def api_scan_results(scan_id):
    """API pour récupérer les résultats d'un scan"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        orchestrator = ScanOrchestrator(current_app.db)
        results = orchestrator.get_scan_results(scan_id, user_id, user_role)
        
        if results:
            return {
                'success': True,
                'results': results
            }
        else:
            return {
                'success': False,
                'error': 'Résultats non disponibles'
            }
            
    except Exception as e:
        logger.error(f"Erreur résultats scan {scan_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/list')
@login_required
def api_list_scans():
    """API pour lister les scans"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Paramètres de pagination
        limit = request.args.get('limit', 20, type=int)
        include_hidden = request.args.get('include_hidden', False, type=bool)
        active_only = request.args.get('active_only', False, type=bool)
        
        # Admin voit tous les scans
        if user_role == 'admin' and request.args.get('all_users', False, type=bool):
            scans = current_app.db.get_scans(
                include_hidden=include_hidden,
                active_only=active_only,
                limit=limit
            )
        else:
            scans = current_app.db.get_scans(
                user_id=user_id,
                include_hidden=include_hidden,
                active_only=active_only,
                limit=limit
            )
        
        return {
            'success': True,
            'scans': scans,
            'count': len(scans)
        }
        
    except Exception as e:
        logger.error(f"Erreur liste scans: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@scans_bp.route('/api/openvas/configs')
@pentester_required
def api_openvas_configs():
    """API pour récupérer les configurations de scan OpenVAS disponibles"""
    try:
        orchestrator = ScanOrchestrator(current_app.db)
        configs = orchestrator.get_available_scan_configs()
        
        return {
            'success': True,
            'configs': configs
        }
        
    except Exception as e:
        logger.error(f"Erreur configs OpenVAS: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

# ===== UTILITAIRES =====

@scans_bp.route('/api/validate-openvas-target', methods=['POST'])
@pentester_required
def api_validate_openvas_target():
    """API pour valider une cible OpenVAS"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return {
                'success': False,
                'error': 'Cible manquante'
            }
        
        # Utiliser la validation Nmap (compatible)
        from core.nmap_wrapper import NmapWrapper
        is_valid, message = NmapWrapper.validate_target(target)
        
        # Vérifications supplémentaires pour OpenVAS si nécessaire
        if is_valid:
            orchestrator = ScanOrchestrator(current_app.db)
            additional_checks = orchestrator.validate_target_for_openvas(target)
            
            return {
                'success': True,
                'valid': is_valid,
                'message': message,
                'additional_info': additional_checks
            }
        else:
            return {
                'success': True,
                'valid': False,
                'message': message
            }
        
    except Exception as e:
        logger.error(f"Erreur validation cible OpenVAS: {e}")
        return {
            'success': False,
            'error': str(e)
        }, 500

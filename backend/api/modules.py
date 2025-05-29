from flask import Blueprint, request, render_template, flash, redirect, url_for, session, current_app, jsonify
from auth import login_required, pentester_required
from services.task_manager import TaskManager
import logging

logger = logging.getLogger('toolbox.modules')

modules_bp = Blueprint('modules', __name__)

# ===== DÉCOUVERTE RÉSEAU =====

@modules_bp.route('/discovery', methods=['GET', 'POST'])
@login_required
def network_discovery():
    """Module de découverte réseau"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        
        if not target:
            flash('Veuillez indiquer une cible à scanner', 'warning')
            return render_template('modules/discovery.html')
        
        try:
            # Validation de la cible
            from core.nmap_wrapper import NmapWrapper
            is_valid, validation_msg = NmapWrapper.validate_target(target)
            
            if not is_valid:
                flash(f'Cible invalide: {validation_msg}', 'danger')
                return render_template('modules/discovery.html')
            
            # Lancer la tâche de découverte
            task_manager = TaskManager(current_app.db)
            task_id = task_manager.start_discovery_task(
                target=target,
                user_id=session.get('user_id'),
                options={
                    'ping_sweep': True,
                    'port_discovery': True,
                    'service_detection': True,
                    'os_detection': True,
                    'aggressive': True
                }
            )
            
            if task_id:
                flash(f'Découverte réseau lancée ! Suivi: {task_id}', 'success')
                return redirect(url_for('tasks.task_status', task_id=task_id))
            else:
                flash('Erreur lors du lancement de la découverte', 'danger')
                
        except Exception as e:
            logger.error(f"Erreur découverte réseau: {e}")
            flash(f'Erreur: {str(e)}', 'danger')
    
    return render_template('modules/discovery.html')

# ===== SCAN NMAP =====

@modules_bp.route('/nmap', methods=['GET', 'POST'])
@login_required
def nmap_scan():
    """Module de scan Nmap"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        scan_type = request.form.get('scan_type', 'quick')
        ports = request.form.get('ports', '').strip()
        
        if not target:
            flash('Veuillez indiquer une cible à scanner', 'warning')
            return render_template('modules/nmap.html')
        
        try:
            # Validation de la cible
            from core.nmap_wrapper import NmapWrapper
            is_valid, validation_msg = NmapWrapper.validate_target(target)
            
            if not is_valid:
                flash(f'Cible invalide: {validation_msg}', 'danger')
                return render_template('modules/nmap.html')
            
            # Lancer la tâche Nmap
            task_manager = TaskManager(current_app.db)
            task_id = task_manager.start_nmap_task(
                target=target,
                scan_type=scan_type,
                ports=ports,
                user_id=session.get('user_id')
            )
            
            if task_id:
                flash(f'Scan Nmap lancé ! Type: {scan_type}', 'success')
                return redirect(url_for('tasks.task_status', task_id=task_id))
            else:
                flash('Erreur lors du lancement du scan', 'danger')
                
        except Exception as e:
            logger.error(f"Erreur scan Nmap: {e}")
            flash(f'Erreur: {str(e)}', 'danger')
    
    return render_template('modules/nmap.html')

# ===== SCAN DE VULNÉRABILITÉS =====

@modules_bp.route('/vulnerability-scan', methods=['GET', 'POST'])
@pentester_required
def vulnerability_scan():
    """Module de scan de vulnérabilités (Nmap NSE)"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        script_category = request.form.get('script_category', 'vuln')
        
        if not target:
            flash('Veuillez indiquer une cible à scanner', 'warning')
            return render_template('modules/vulnerability_scan.html')
        
        try:
            # Validation de la cible
            from core.nmap_wrapper import NmapWrapper
            is_valid, validation_msg = NmapWrapper.validate_target(target)
            
            if not is_valid:
                flash(f'Cible invalide: {validation_msg}', 'danger')
                return render_template('modules/vulnerability_scan.html')
            
            # Lancer la tâche de scan de vulnérabilités
            task_manager = TaskManager(current_app.db)
            task_id = task_manager.start_vulnerability_task(
                target=target,
                scripts=script_category,
                user_id=session.get('user_id')
            )
            
            if task_id:
                flash(f'Scan de vulnérabilités lancé ! Scripts: {script_category}', 'success')
                return redirect(url_for('tasks.task_status', task_id=task_id))
            else:
                flash('Erreur lors du lancement du scan', 'danger')
                
        except Exception as e:
            logger.error(f"Erreur scan vulnérabilités: {e}")
            flash(f'Erreur: {str(e)}', 'danger')
    
    return render_template('modules/vulnerability_scan.html')

# ===== API ENDPOINTS =====

@modules_bp.route('/api/available')
@login_required
def api_available_modules():
    """Liste des modules disponibles"""
    modules = [
        {
            'name': 'discovery',
            'title': 'Découverte Réseau',
            'description': 'Identification des hôtes actifs sur le réseau',
            'icon': '🌐',
            'url': url_for('modules.network_discovery'),
            'min_role': 'viewer'
        },
        {
            'name': 'nmap',
            'title': 'Scan Nmap',
            'description': 'Scan de ports et énumération de services',
            'icon': '🔍',
            'url': url_for('modules.nmap_scan'),
            'min_role': 'viewer'
        },
        {
            'name': 'vulnerability',
            'title': 'Scan Vulnérabilités',
            'description': 'Détection de vulnérabilités avec scripts NSE',
            'icon': '⚠️',
            'url': url_for('modules.vulnerability_scan'),
            'min_role': 'pentester'
        }
    ]
    
    # Filtrer selon le rôle de l'utilisateur
    user_role = session.get('role', 'viewer')
    role_hierarchy = {'viewer': 1, 'pentester': 2, 'admin': 3}
    user_level = role_hierarchy.get(user_role, 0)
    
    available_modules = [
        module for module in modules
        if role_hierarchy.get(module['min_role'], 999) <= user_level
    ]
    
    return {
        'success': True,
        'modules': available_modules,
        'user_role': user_role
    }

@modules_bp.route('/api/<module_name>/info')
@login_required
def api_module_info(module_name):
    """Informations détaillées sur un module"""
    try:
        if module_name == 'discovery':
            from modules.decouverte_reseau import DecouverteReseauModule
            module = DecouverteReseauModule()
            return {
                'success': True,
                'info': module.get_module_info()
            }
        else:
            return {
                'success': False,
                'error': f'Module {module_name} non trouvé'
            }
    except Exception as e:
        logger.error(f"Erreur info module {module_name}: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# ===== VALIDATION ET UTILITAIRES =====

@modules_bp.route('/api/validate-target', methods=['POST'])
@login_required
def api_validate_target():
    """Valide une cible avant scan"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return {
                'success': False,
                'error': 'Cible manquante'
            }
        
        from core.nmap_wrapper import NmapWrapper
        is_valid, message = NmapWrapper.validate_target(target)
        
        return {
            'success': True,
            'valid': is_valid,
            'message': message
        }
        
    except Exception as e:
        logger.error(f"Erreur validation cible: {e}")
        return {
            'success': False,
            'error': str(e)
        }

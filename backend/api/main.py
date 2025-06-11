from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from auth import login_required, admin_required
from security.backup.backup_service import BackupService
import logging

logger = logging.getLogger('toolbox.main')

main_bp = Blueprint('main', __name__)

# ===== ROUTES D'AUTHENTIFICATION =====

@main_bp.route('/')
def index():
    """Page d'accueil - redirige vers dashboard si connecté"""
    if current_app.auth.is_authenticated():
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis', 'warning')
            return render_template('auth/login.html')
        
        if current_app.auth.login_user(username, password):
            flash('Connexion réussie', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Identifiants incorrects', 'danger')
    
    return render_template('auth/login.html')

@main_bp.route('/logout')
@login_required
def logout():
    """Déconnexion"""
    current_app.auth.logout_user()
    flash('Déconnexion réussie', 'info')
    return redirect(url_for('main.login'))

# ===== DASHBOARD =====

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal - Version vierge"""
    try:
        # Récupérer les statistiques de base
        stats = current_app.db.get_stats()
        
        # Récupérer les tâches récentes de l'utilisateur
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Admin voit toutes les tâches, autres seulement les leurs
        if user_role == 'admin':
            recent_tasks = current_app.db.get_tasks(limit=5)
        else:
            recent_tasks = current_app.db.get_tasks(user_id=user_id, limit=5)
                
        return render_template('dashboard/dashboard.html', 
                             stats=stats or {},
                             recent_tasks=recent_tasks or [])
                             
    except Exception as e:
        logger.error(f"Erreur dashboard: {e}")
        # En cas d'erreur, renvoyer des valeurs par défaut
        return render_template('dashboard/dashboard.html', 
                             stats={}, 
                             recent_tasks=[])

@main_bp.route('/profile')
@login_required
def profile():
    """Profil utilisateur"""
    user = current_app.auth.get_current_user()
    return render_template('auth/profile.html', user=user)

# ===== GESTION DES UTILISATEURS (ADMIN) =====

@main_bp.route('/users')
@admin_required
def users_list():
    """Liste des utilisateurs (admin seulement)"""
    try:
        users = current_app.db.get_users()
        return render_template('auth/users.html', users=users)
    except Exception as e:
        logger.error(f"Erreur liste utilisateurs: {e}")
        flash('Erreur lors du chargement des utilisateurs', 'danger')
        return render_template('auth/users.html', users=[])

@main_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    """Créer un nouvel utilisateur"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'viewer')
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis', 'warning')
            return render_template('auth/create_user.html')
        
        if len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères', 'warning')
            return render_template('auth/create_user.html')
        
        if role not in ['viewer', 'pentester', 'admin']:
            flash('Rôle invalide', 'warning')
            return render_template('auth/create_user.html')
        
        if current_app.auth.create_user(username, password, role):
            flash(f'Utilisateur {username} créé avec succès', 'success')
            return redirect(url_for('main.users_list'))
        else:
            flash('Erreur lors de la création (utilisateur existe peut-être déjà)', 'danger')
    
    return render_template('auth/create_user.html')

# ===== PAGES D'INFORMATION =====

@main_bp.route('/about')
def about():
    """Page à propos"""
    return render_template('about.html')

@main_bp.route('/help')
@login_required
def help_page():
    """Page d'aide"""
    return render_template('help.html')

# ===== API ENDPOINTS UTILITAIRES =====

@main_bp.route('/api/status')
def api_status():
    """Status de l'application"""
    return {
        'status': 'ok',
        'version': '2.0',
        'mode': 'clean_infrastructure',
        'authenticated': current_app.auth.is_authenticated(),
        'user': current_app.auth.get_current_user() if current_app.auth.is_authenticated() else None
    }

@main_bp.route('/api/stats')
@login_required
def api_stats():
    """Statistiques générales"""
    try:
        stats = current_app.db.get_stats()
        return {'success': True, 'stats': stats}
    except Exception as e:
        logger.error(f"Erreur API stats: {e}")
        return {'success': False, 'error': str(e)}, 500



# ===== ROUTES DE GESTION DES SAUVEGARDES (ADMIN) =====

@main_bp.route('/admin/backups')
@admin_required
def backup_management():
    """Interface de gestion des sauvegardes MinIO"""
    try:
        if hasattr(current_app, 'minio_client') and current_app.minio_client.is_available():
            backup_service = BackupService(current_app.minio_client.get_client(), current_app.db)
            backups = backup_service.list_backups()
            storage_stats = backup_service.get_storage_stats()
            
            return render_template('admin/backups.html', 
                                 backups=backups, 
                                 storage_stats=storage_stats,
                                 minio_status=current_app.minio_client.get_status())
        else:
            flash('MinIO non disponible', 'danger')
            return render_template('admin/backups.html', 
                                 backups=[], 
                                 storage_stats={},
                                 minio_status={'available': False})
    except Exception as e:
        logger.error(f"Erreur gestion sauvegardes: {e}")
        flash(f'Erreur: {e}', 'danger')
        return render_template('admin/backups.html', 
                             backups=[], 
                             storage_stats={},
                             minio_status={'available': False})

@main_bp.route('/admin/backup/create', methods=['POST'])
@admin_required  
def create_backup():
    """Créer une sauvegarde complète"""
    try:
        if not hasattr(current_app, 'minio_client') or not current_app.minio_client.is_available():
            return jsonify({
                'success': False,
                'error': 'MinIO non disponible'
            }), 503
        
        description = request.json.get('description', 'Manual backup') if request.is_json else request.form.get('description', 'Manual backup')
        
        backup_service = BackupService(current_app.minio_client.get_client(), current_app.db)
        result = backup_service.create_full_backup(description)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f"Sauvegarde créée: {result['backup_id']}",
                'backup_id': result['backup_id'],
                'files_count': result.get('files_count', 0)
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Erreur inconnue')
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur création sauvegarde: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main_bp.route('/admin/backup/restore/<backup_id>', methods=['POST'])
@admin_required
def restore_backup(backup_id: str):
    """Restaurer une sauvegarde"""
    try:
        if not hasattr(current_app, 'minio_client') or not current_app.minio_client.is_available():
            return jsonify({
                'success': False,
                'error': 'MinIO non disponible'
            }), 503
        
        backup_service = BackupService(current_app.minio_client.get_client(), current_app.db)
        result = backup_service.restore_backup(backup_id)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f"Sauvegarde restaurée: {backup_id}",
                'restored_components': result.get('restored_components', [])
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Erreur inconnue')
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur restauration: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main_bp.route('/admin/backup/delete/<backup_id>', methods=['DELETE'])
@admin_required
def delete_backup(backup_id: str):
    """Supprimer une sauvegarde"""
    try:
        if not hasattr(current_app, 'minio_client') or not current_app.minio_client.is_available():
            return jsonify({
                'success': False,
                'error': 'MinIO non disponible'
            }), 503
        
        backup_service = BackupService(current_app.minio_client.get_client(), current_app.db)
        success = backup_service.delete_backup(backup_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': f"Sauvegarde supprimée: {backup_id}"
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Impossible de supprimer la sauvegarde'
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur suppression backup: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main_bp.route('/admin/backup/details/<backup_id>')
@admin_required
def backup_details(backup_id: str):
    """Détails d'une sauvegarde"""
    try:
        if not hasattr(current_app, 'minio_client') or not current_app.minio_client.is_available():
            return jsonify({
                'success': False,
                'error': 'MinIO non disponible'
            }), 503
        
        backup_service = BackupService(current_app.minio_client.get_client(), current_app.db)
        details = backup_service.get_backup_details(backup_id)
        
        if details:
            # Ajouter la taille
            size = backup_service.get_backup_size(backup_id)
            details['total_size_bytes'] = size
            details['total_size_mb'] = round(size / (1024 * 1024), 2)
            
            return jsonify({
                'success': True,
                'details': details
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Sauvegarde non trouvée'
            }), 404
            
    except Exception as e:
        logger.error(f"Erreur détails backup: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ===== ROUTES DE GESTION DES CLÉS (ADMIN) =====

@main_bp.route('/admin/security')
@admin_required
def security_management():
    """Interface de gestion de la sécurité"""
    try:
        security_status = current_app.db.get_security_status() if hasattr(current_app.db, 'get_security_status') else {}
        
        return render_template('admin/security.html', 
                             security_status=security_status)
    except Exception as e:
        logger.error(f"Erreur gestion sécurité: {e}")
        return render_template('admin/security.html', 
                             security_status={})

@main_bp.route('/admin/security/test-encryption', methods=['POST'])
@admin_required
def test_encryption():
    """Tester le système de chiffrement"""
    try:
        if hasattr(current_app.db, 'test_encryption'):
            success = current_app.db.test_encryption()
            return jsonify({
                'success': success,
                'message': 'Test de chiffrement réussi' if success else 'Test de chiffrement échoué'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Service de chiffrement non disponible'
            }), 503
            
    except Exception as e:
        logger.error(f"Erreur test chiffrement: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main_bp.route('/admin/security/rotate-key', methods=['POST'])
@admin_required
def rotate_encryption_key():
    """Rotation de la clé de chiffrement"""
    try:
        if hasattr(current_app.db, 'crypto_service') and current_app.db.crypto_service:
            success = current_app.db.crypto_service.rotate_encryption_key()
            return jsonify({
                'success': success,
                'message': 'Rotation de clé réussie' if success else 'Rotation de clé échouée'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Service de chiffrement non disponible'
            }), 503
            
    except Exception as e:
        logger.error(f"Erreur rotation clé: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

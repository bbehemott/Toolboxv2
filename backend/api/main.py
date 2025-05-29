from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from auth import login_required, admin_required
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

# ===== DASHBOARD ET PAGES PRINCIPALES =====

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal"""
    try:
        # Récupérer les statistiques
        stats = current_app.db.get_stats()
        
        # Récupérer les tâches récentes de l'utilisateur
        user_id = session.get('user_id')
        recent_tasks = current_app.db.get_tasks(user_id=user_id, limit=5)
        recent_scans = current_app.db.get_scans(user_id=user_id, limit=5)
        
        return render_template('dashboard/dashboard.html', 
                             stats=stats,
                             recent_tasks=recent_tasks,
                             recent_scans=recent_scans)
    except Exception as e:
        logger.error(f"Erreur dashboard: {e}")
        flash('Erreur lors du chargement du dashboard', 'danger')
        return render_template('dashboard/dashboard.html', stats={}, recent_tasks=[], recent_scans=[])

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

@main_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    """Activer/désactiver un utilisateur"""
    # Cette fonctionnalité sera implémentée dans la base de données
    flash('Fonctionnalité pas encore implémentée', 'warning')
    return redirect(url_for('main.users_list'))

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
        'authenticated': current_app.auth.is_authenticated(),
        'user': current_app.auth.get_current_user() if current_app.auth.is_authenticated() else None
    }

@main_bp.route('/api/stats')
@login_required
def api_stats():
    """Statiques générales"""
    try:
        stats = current_app.db.get_stats()
        return {'success': True, 'stats': stats}
    except Exception as e:
        logger.error(f"Erreur API stats: {e}")
        return {'success': False, 'error': str(e)}, 500

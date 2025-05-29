from functools import wraps
from flask import session, request, redirect, url_for, flash, jsonify
import logging

logger = logging.getLogger('toolbox.auth')

class AuthManager:
    """Gestionnaire d'authentification et d'autorisation"""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    def login_user(self, username: str, password: str) -> bool:
        """Connecte un utilisateur"""
        try:
            user = self.db.authenticate_user(username, password)
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = False
                
                logger.info(f"Connexion réussie: {username} ({user['role']})")
                return True
            else:
                logger.warning(f"Échec connexion: {username}")
                return False
        except Exception as e:
            logger.error(f"Erreur login: {e}")
            return False
    
    def logout_user(self):
        """Déconnecte l'utilisateur"""
        username = session.get('username', 'Unknown')
        session.clear()
        logger.info(f"Déconnexion: {username}")
    
    def get_current_user(self) -> dict:
        """Récupère l'utilisateur actuel"""
        return {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'role': session.get('role'),
            'is_authenticated': 'user_id' in session
        }
    
    def is_authenticated(self) -> bool:
        """Vérifie si l'utilisateur est connecté"""
        return 'user_id' in session
    
    def has_role(self, required_role: str) -> bool:
        """Vérifie si l'utilisateur a le rôle requis"""
        user_role = session.get('role')
        if not user_role:
            return False
        
        # Hiérarchie des rôles
        role_hierarchy = {
            'viewer': 1,
            'pentester': 2,
            'admin': 3
        }
        
        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(required_role, 999)
        
        return user_level >= required_level
    
    def create_user(self, username: str, password: str, role: str = 'viewer') -> bool:
        """Crée un nouvel utilisateur (admin seulement)"""
        if not self.has_role('admin'):
            return False
        
        try:
            user_id = self.db.create_user(username, password, role)
            if user_id:
                logger.info(f"Utilisateur créé: {username} ({role}) par {session.get('username')}")
                return True
            return False
        except Exception as e:
            logger.error(f"Erreur création utilisateur: {e}")
            return False

# Décorateurs pour les routes

def login_required(f):
    """Décorateur pour exiger une connexion"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            else:
                flash('Connexion requise', 'warning')
                return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    """Décorateur pour exiger un rôle spécifique"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                else:
                    flash('Connexion requise', 'warning')
                    return redirect(url_for('main.login'))
            
            user_role = session.get('role')
            role_hierarchy = {
                'viewer': 1,
                'pentester': 2,
                'admin': 3
            }
            
            user_level = role_hierarchy.get(user_role, 0)
            required_level = role_hierarchy.get(required_role, 999)
            
            if user_level < required_level:
                if request.is_json:
                    return jsonify({'error': f'Role {required_role} required'}), 403
                else:
                    flash(f'Droits insuffisants (rôle {required_role} requis)', 'danger')
                    return redirect(url_for('main.dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Décorateur pour exiger les droits admin"""
    return role_required('admin')(f)

def pentester_required(f):
    """Décorateur pour exiger les droits pentester ou plus"""
    return role_required('pentester')(f)

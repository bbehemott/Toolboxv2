from flask import Blueprint, request, render_template, session, current_app, jsonify
from auth import login_required, admin_required
from services.task_manager import TaskManager
import logging

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
    """API pour récupérer le statut d'une tâche"""
    try:
        task_manager = TaskManager(current_app.db)
        status = task_manager.get_task_status(task_id)
        
        if not status:
            return {
                'success': False,
                'error': 'Tâche non trouvée'
            }, 404
        
        return {
            'success': True,
            'status': status
        }
        
    except Exception as e:
        logger.error(f"Erreur API statut tâche {task_id}: {e}")
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
        
        # Paramètres de pagination
        limit = request.args.get('limit', 20, type=int)
        include_hidden = request.args.get('include_hidden', False, type=bool)
        
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
        days = request.json.get('days', 30)
        
        if not isinstance(days, int) or days < 1:
            return {
                'success': False,
                'error': 'Nombre de jours invalide'
            }
        
        cleaned_count = current_app.db.cleanup_old_tasks(days)
        
        return {
            'success': True,
            'message': f'{cleaned_count} tâches nettoyées',
            'cleaned_count': cleaned_count
        }
        
    except Exception as e:
        logger.error(f"Erreur nettoyage tâches: {e}")
        return {
            'success': False,
            'error': str(e)
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

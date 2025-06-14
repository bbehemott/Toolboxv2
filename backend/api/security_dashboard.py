from flask import Blueprint, render_template
from auth import login_required

dashboard_bp = Blueprint('security_dashboard', __name__)

@dashboard_bp.route('/security/dashboard')
@login_required
def security_dashboard():
    """Page du dashboard sécurité"""
    return render_template('security/dashboard.html')

def register_security_dashboard(app):
    """Enregistrer le dashboard"""
    app.register_blueprint(dashboard_bp)

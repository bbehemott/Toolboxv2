import os
import logging
from flask import Flask
from logging.handlers import RotatingFileHandler
from pygelf import GelfUdpHandler
from api.huntkit import huntkit_bp
from config import config
from database import DatabaseManager
from auth import AuthManager
from security import MinIOClient
from api.security import register_security_api
from api.security_dashboard import register_security_dashboard

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('toolbox')

def create_app(config_name=None):
    """Factory pattern pour créer l'application Flask"""
    
    # Déterminer la configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    app_config = config.get(config_name, config['default'])
    
    # Créer l'application Flask
    app = Flask(__name__)
    app.config.from_object(app_config)
    
    # Initialiser les répertoires
    app_config.init_directories()
    
    # Valider la configuration
    app_config.validate_config()
    
    # Configurer le logging
    setup_logging(app, app_config)
    
    # Initialiser la base de données
    db_manager = DatabaseManager(app_config.DATABASE_URL)
    db_manager.create_default_admin()
    
    # Initialiser l'authentification
    auth_manager = AuthManager(db_manager)

    try:
        minio_client = MinIOClient()
        if minio_client.is_available():
            logger.info("🗂️ MinIO disponible - Services de sécurité activés")
        else:
            logger.warning("⚠️ MinIO non disponible - Fonctionnement en mode dégradé")
        app.minio_client = minio_client
    except Exception as e:
        logger.error(f"❌ Erreur initialisation MinIO: {e}")
        app.minio_client = None

    # Rendre disponibles globalement
    app.db = db_manager
    app.auth = auth_manager
    
    # Enregistrer les blueprints (routes)
    register_blueprints(app)
    
    # Gestionnaires d'erreur
    register_error_handlers(app)
    
    # Context processors pour les templates
    register_template_helpers(app)

    register_security_api(app)

    register_security_dashboard(app)

    log_services_status(app)

    logger.info(f"Application démarrée en mode {config_name}")
    return app

def setup_logging(app, app_config):
    """Configure le système de logging"""
    
    if not app.debug:
        # Logging vers fichier
        if not app_config.LOGS_DIR.exists():
            app_config.LOGS_DIR.mkdir(parents=True)
        
        file_handler = RotatingFileHandler(
            app_config.LOGS_DIR / 'toolbox.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)-8s [%(name)s] %(message)s'
        ))
        file_handler.setLevel(logging.INFO)
        
        # Logging vers Graylog
        try:
            gelf_handler = GelfUdpHandler(
                host=app_config.GRAYLOG_HOST,
                port=app_config.GRAYLOG_PORT
            )
            logger.addHandler(gelf_handler)
        except Exception as e:
            logger.warning(f"Impossible de connecter à Graylog: {e}")
        
        logger.addHandler(file_handler)
        logger.setLevel(getattr(logging, app_config.LOG_LEVEL))


def register_blueprints(app):
    """Enregistre tous les blueprints (routes)"""
    
    # Routes principales (PAS de préfixe)
    from api.main import main_bp
    app.register_blueprint(main_bp)
    
    # API modules (préfixe /modules pour compatibilité templates)
    from api.modules import modules_bp
    app.register_blueprint(modules_bp, url_prefix='/modules')
    
    # API tâches (préfixe /tasks pour compatibilité templates) 
    from api.tasks import tasks_bp
    app.register_blueprint(tasks_bp, url_prefix='/tasks')
    
    # ===== NOUVEAU : API HuntKit =====
    from api.huntkit import huntkit_bp
    app.register_blueprint(huntkit_bp, url_prefix='/huntkit')

    from api.traffic import traffic_bp
    app.register_blueprint(traffic_bp, url_prefix='/traffic')

    #Blueprint monitoring
    from api.monitoring import monitoring_bp
    app.register_blueprint(monitoring_bp, url_prefix='/monitoring')

def log_services_status(app):
    """Affiche le statut des services au démarrage"""
    logger.info("=== STATUT DES SERVICES ===")
    
    # PostgreSQL
    try:
        stats = app.db.get_stats()
        logger.info("✅ PostgreSQL: Opérationnel")
    except Exception as e:
        logger.error(f"❌ PostgreSQL: {e}")
    
    # MinIO
    if hasattr(app, 'minio_client') and app.minio_client:
        status = app.minio_client.get_status()
        if status['available']:
            logger.info(f"✅ MinIO: Opérationnel ({len(status['buckets'])} buckets)")
        else:
            logger.warning("⚠️ MinIO: Non disponible")
    else:
        logger.warning("⚠️ MinIO: Non configuré")
    
    # Services de sécurité
    if hasattr(app.db, 'crypto_service') and app.db.crypto_service:
        if app.db.crypto_service.is_available():
            logger.info("✅ Chiffrement: Opérationnel")
        else:
            logger.warning("⚠️ Chiffrement: Non disponible")
    else:
        logger.warning("⚠️ Chiffrement: Non configuré")
    
    logger.info("=== FIN STATUT ===")


def register_error_handlers(app):
    """Enregistre les gestionnaires d'erreur"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        return {'error': 'Page non trouvée'}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Erreur interne: {error}")
        return {'error': 'Erreur interne du serveur'}, 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return {'error': 'Accès interdit'}, 403

def register_template_helpers(app):
    """Enregistre les helpers pour les templates"""
    
    @app.context_processor
    def inject_user():
        """Injecte les informations utilisateur dans tous les templates"""
        return {
            'current_user': app.auth.get_current_user(),
            'app_name': 'Toolbox Cybersécurité ESI M1',
            'app_version': '2.0',
            'minio_available': hasattr(app, 'minio_client') and app.minio_client and app.minio_client.is_available()
        }

# Point d'entrée principal
if __name__ == '__main__':
    app = create_app()
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config.get('DEBUG', False)
    )

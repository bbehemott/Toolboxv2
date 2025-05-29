import os
from pathlib import Path

class Config:
    """Configuration de base"""
    
    # Répertoires
    BASE_DIR = Path(__file__).parent
    DATABASE_PATH = BASE_DIR / 'toolbox.db'
    LOGS_DIR = BASE_DIR / 'logs'
    
    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    
    # OpenVAS
    OPENVAS_HOST = os.getenv('OPENVAS_HOST', 'openvas')
    OPENVAS_PORT = int(os.getenv('OPENVAS_PORT', '9390'))
    OPENVAS_USER = os.getenv('OPENVAS_USER', 'admin')
    OPENVAS_PASSWORD = os.getenv('OPENVAS_PASSWORD', 'admin')
    
    # Timeouts
    DEFAULT_SCAN_TIMEOUT = 3600  # 1 heure
    DEFAULT_NMAP_TIMEOUT = 300   # 5 minutes
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    GRAYLOG_HOST = os.getenv('GRAYLOG_HOST', '127.0.0.1')
    GRAYLOG_PORT = int(os.getenv('GRAYLOG_PORT', '12201'))
    
    # Sécurité
    BCRYPT_ROUNDS = 12
    SESSION_PERMANENT = False
    SESSION_COOKIE_SECURE = False  # True en production avec HTTPS
    SESSION_COOKIE_HTTPONLY = True
    
    @classmethod
    def init_directories(cls):
        """Crée les répertoires nécessaires"""
        cls.LOGS_DIR.mkdir(exist_ok=True)
        
    @classmethod
    def validate_config(cls):
        """Valide la configuration"""
        required_env = []
        
        missing = [var for var in required_env if not os.getenv(var)]
        if missing:
            raise ValueError(f"Variables d'environnement manquantes: {missing}")
        
        return True

class DevelopmentConfig(Config):
    """Configuration de développement"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Configuration de production"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    """Configuration de test"""
    TESTING = True
    DATABASE_PATH = ':memory:'

# Configuration par défaut
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

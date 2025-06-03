import os
from pathlib import Path

class Config:
    """Configuration PostgreSQL uniquement"""
    
    # Répertoires
    BASE_DIR = Path(__file__).parent
    LOGS_DIR = BASE_DIR / 'logs'
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # PostgreSQL UNIQUEMENT - Pas de SQLite
    DB_HOST = os.getenv('DB_HOST', 'postgres')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_NAME = os.getenv('DB_NAME', 'toolbox')
    DB_USER = os.getenv('DB_USER', 'toolbox_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'toolbox_password')
    
    # URL PostgreSQL
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    
    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    
    # Timeouts
    DEFAULT_SCAN_TIMEOUT = 3600
    DEFAULT_NMAP_TIMEOUT = 300
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    GRAYLOG_HOST = os.getenv('GRAYLOG_HOST', '127.0.0.1')
    GRAYLOG_PORT = int(os.getenv('GRAYLOG_PORT', '12201'))
    
    # Sécurité
    BCRYPT_ROUNDS = 12
    SESSION_PERMANENT = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    
    @classmethod
    def init_directories(cls):
        """Crée les répertoires nécessaires"""
        cls.LOGS_DIR.mkdir(exist_ok=True)
        
    @classmethod
    def validate_config(cls):
        """Valide la configuration PostgreSQL"""
        required_env = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']
        
        missing = [var for var in required_env if not os.getenv(var)]
        if missing:
            raise ValueError(f"Variables d'environnement manquantes: {missing}")
        
        # Test de connexion PostgreSQL
        try:
            import psycopg2
            test_url = f"postgresql://{cls.DB_USER}:{cls.DB_PASSWORD}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
            conn = psycopg2.connect(test_url)
            conn.close()
            print("✅ Configuration PostgreSQL validée")
        except Exception as e:
            raise ValueError(f"❌ Impossible de se connecter à PostgreSQL: {e}")
        
        return True

class DevelopmentConfig(Config):
    """Configuration de développement PostgreSQL"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Configuration de production PostgreSQL"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    # Utiliser une base séparée en production
    DB_NAME = os.getenv('DB_NAME', 'toolbox_prod')

class TestingConfig(Config):
    """Configuration de test PostgreSQL"""
    TESTING = True
    DB_NAME = os.getenv('DB_NAME', 'toolbox_test')

# Configuration par défaut - PostgreSQL uniquement
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

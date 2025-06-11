"""
Client MinIO pour la toolbox - Tâches 21, 23, 40
Intégration compatible avec l'architecture Flask + PostgreSQL existante
"""
import os
from minio import Minio
from minio.error import S3Error
import logging

logger = logging.getLogger('toolbox.minio')

class MinIOClient:
    """Client MinIO pour la toolbox de pentesting"""
    
    def __init__(self, endpoint=None, access_key=None, secret_key=None, secure=False):
        # Configuration depuis les variables d'environnement
        self.endpoint = endpoint or os.getenv('MINIO_ENDPOINT', 'minio:9000')
        self.access_key = access_key or os.getenv('MINIO_ROOT_USER', 'toolbox_admin')
        self.secret_key = secret_key or os.getenv('MINIO_ROOT_PASSWORD', 'toolbox_secret_2024')
        self.secure = secure or os.getenv('MINIO_SECURE', 'false').lower() == 'true'
        
        self.client = None
        self._initialize_client()
        self._ensure_buckets()
    
    def _initialize_client(self):
        """Initialise le client MinIO"""
        try:
            self.client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure
            )
            logger.info(f"🗂️ Client MinIO initialisé: {self.endpoint}")
        except Exception as e:
            logger.error(f"❌ Erreur initialisation MinIO: {e}")
            self.client = None
    
    def _ensure_buckets(self):
        """Crée les buckets nécessaires pour les tâches 21, 23, 40"""
        if not self.client:
            logger.warning("⚠️ Client MinIO non disponible pour création buckets")
            return
        
        required_buckets = {
            'encryption-keys': 'Stockage sécurisé des clés de chiffrement (Tâche 23)',
            'backups': 'Sauvegardes complètes système (Tâche 40)', 
            'scan-evidences': 'Preuves et captures des scans (Tâche 21)'
        }
        
        for bucket_name, description in required_buckets.items():
            try:
                if not self.client.bucket_exists(bucket_name):
                    self.client.make_bucket(bucket_name)
                    logger.info(f"📦 Bucket créé: {bucket_name} - {description}")
                else:
                    logger.debug(f"📦 Bucket existant: {bucket_name}")
            except S3Error as e:
                logger.error(f"❌ Erreur bucket {bucket_name}: {e}")
    
    def get_client(self):
        """Retourne le client MinIO pour utilisation"""
        return self.client
    
    def is_available(self) -> bool:
        """Vérifie si MinIO est disponible"""
        if not self.client:
            return False
        
        try:
            # Test simple avec list_buckets
            self.client.list_buckets()
            return True
        except Exception as e:
            logger.warning(f"⚠️ MinIO non accessible: {e}")
            return False
    
    def get_status(self) -> dict:
        """Retourne le statut de MinIO"""
        status = {
            'available': self.is_available(),
            'endpoint': self.endpoint,
            'secure': self.secure,
            'buckets': []
        }
        
        if status['available']:
            try:
                buckets = self.client.list_buckets()
                status['buckets'] = [bucket.name for bucket in buckets]
            except Exception as e:
                logger.error(f"❌ Erreur récupération buckets: {e}")
        
        return status

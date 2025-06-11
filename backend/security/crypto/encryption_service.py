"""
Service de chiffrement utilisant les clés MinIO - Tâche 21
Intégré avec l'architecture Flask + PostgreSQL existante
"""
from cryptography.fernet import Fernet
from key_management import KeyManagementService
from typing import Optional, Dict
import logging

logger = logging.getLogger('toolbox.crypto')

class EncryptionService:
    """Service de chiffrement utilisant les clés MinIO (CONFORME TÂCHE 21)"""
    
    def __init__(self, key_manager: KeyManagementService):
        self.key_manager = key_manager
        self._fernet = None
        self._initialize_fernet()
    
    def _initialize_fernet(self):
        """Initialise Fernet avec la clé de MinIO"""
        try:
            key = self.key_manager.get_current_encryption_key()
            if key:
                self._fernet = Fernet(key.encode())
                logger.info("🔐 Service de chiffrement initialisé avec clé MinIO")
            else:
                logger.error("❌ Impossible d'initialiser le chiffrement")
                self._fernet = None
        except Exception as e:
            logger.error(f"❌ Erreur init chiffrement: {e}")
            self._fernet = None
    
    def encrypt(self, data: str) -> str:
        """Chiffre une chaîne avec Fernet (Tâche 21)"""
        if not self._fernet:
            logger.warning("⚠️ Service de chiffrement non disponible")
            return data
        
        try:
            if not data or len(data) == 0:
                return data
            
            # Vérifier si déjà chiffré (commence par gAAAAAB)
            if data.startswith('gAAAAAB'):
                logger.debug("🔐 Données déjà chiffrées, skipping")
                return data
            
            encrypted_bytes = self._fernet.encrypt(data.encode())
            encrypted_str = encrypted_bytes.decode()
            
            logger.debug(f"🔐 Données chiffrées: {len(data)} → {len(encrypted_str)} chars")
            return encrypted_str
            
        except Exception as e:
            logger.error(f"❌ Erreur chiffrement: {e}")
            return data
    
    def decrypt(self, encrypted_data: str) -> str:
        """Déchiffre une chaîne"""
        if not self._fernet or not encrypted_data:
            return encrypted_data
        
        try:
            # Détecter si c'est chiffré (commence par gAAAAAB)
            if not encrypted_data.startswith('gAAAAAB'):
                logger.debug("🔓 Données non chiffrées, retour direct")
                return encrypted_data
            
            decrypted_bytes = self._fernet.decrypt(encrypted_data.encode())
            decrypted_str = decrypted_bytes.decode()
            
            logger.debug(f"🔓 Données déchiffrées: {len(encrypted_data)} → {len(decrypted_str)} chars")
            return decrypted_str
            
        except Exception as e:
            logger.error(f"❌ Erreur déchiffrement: {e}")
            # Retourner les données telles quelles si déchiffrement impossible
            return encrypted_data
    
    def encrypt_sensitive_data(self, data: str, data_type: str = "general") -> str:
        """Chiffre les données sensibles (raw_output, credentials, etc.)"""
        if not data:
            return data
        
        encrypted = self.encrypt(data)
        logger.info(f"🔐 Données sensibles chiffrées: type={data_type}, original_size={len(data)} chars")
        return encrypted
    
    def decrypt_sensitive_data(self, encrypted_data: str, data_type: str = "general") -> str:
        """Déchiffre les données sensibles"""
        if not encrypted_data:
            return encrypted_data
        
        decrypted = self.decrypt(encrypted_data)
        logger.debug(f"🔓 Données sensibles déchiffrées: type={data_type}")
        return decrypted
    
    def encrypt_credentials(self, username: str, password: str) -> Dict[str, str]:
        """Chiffre les credentials de façon sécurisée"""
        return {
            'username': self.encrypt_sensitive_data(username, "username"),
            'password': self.encrypt_sensitive_data(password, "password")
        }
    
    def decrypt_credentials(self, encrypted_creds: Dict[str, str]) -> Dict[str, str]:
        """Déchiffre les credentials"""
        return {
            'username': self.decrypt_sensitive_data(encrypted_creds.get('username', ''), "username"),
            'password': self.decrypt_sensitive_data(encrypted_creds.get('password', ''), "password")
        }
    
    def rotate_encryption_key(self) -> bool:
        """Rotation de la clé de chiffrement"""
        try:
            success = self.key_manager.rotate_master_key()
            if success:
                # Réinitialiser Fernet avec la nouvelle clé
                self._initialize_fernet()
                logger.info("🔄 Clé de chiffrement rotée avec succès")
                return True
            else:
                logger.error("❌ Échec rotation clé de chiffrement")
                return False
        except Exception as e:
            logger.error(f"❌ Erreur rotation clé: {e}")
            return False
    
    def test_encryption_cycle(self) -> bool:
        """Teste le cycle chiffrement/déchiffrement"""
        try:
            test_data = "Test encryption cycle - Toolbox ESI M1 Cyber"
            
            # Chiffrer
            encrypted = self.encrypt(test_data)
            if encrypted == test_data:
                logger.warning("⚠️ Chiffrement non effectué")
                return False
            
            # Déchiffrer
            decrypted = self.decrypt(encrypted)
            if decrypted != test_data:
                logger.error("❌ Cycle chiffrement/déchiffrement échoué")
                return False
            
            logger.info("✅ Test cycle chiffrement/déchiffrement réussi")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur test chiffrement: {e}")
            return False
    
    def get_encryption_status(self) -> Dict:
        """Statut du service de chiffrement"""
        status = {
            'service': 'EncryptionService',
            'available': self._fernet is not None,
            'algorithm': 'Fernet (AES-128)',
            'storage': 'MinIO S3-compatible',
            'key_info': self.key_manager.get_key_info(),
            'test_passed': False
        }
        
        if status['available']:
            status['test_passed'] = self.test_encryption_cycle()
        
        return status
    
    def is_available(self) -> bool:
        """Vérifie si le service de chiffrement est disponible"""
        return self._fernet is not None

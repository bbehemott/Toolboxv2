"""
Service de gestion des clés utilisant MinIO - Tâche 23
Intégré avec l'architecture Flask + PostgreSQL existante
"""
import os
from datetime import datetime
from typing import Dict, List, Optional
from cryptography.fernet import Fernet
from .minio_key_store import MinIOKeyStore
import logging

logger = logging.getLogger('toolbox.key_manager')

class KeyManagementService:
    """Gestionnaire de clés utilisant MinIO (CONFORME TÂCHE 23)"""
    
    def __init__(self, minio_client):
        self.key_store = MinIOKeyStore(minio_client)
        self.current_key_id = 'master_key'
        self._initialize_master_key()
    
    def _initialize_master_key(self):
        """Initialise ou récupère la clé maître"""
        try:
            # Essayer de récupérer la clé existante
            master_key = self.key_store.retrieve_key(self.current_key_id)
            
            if not master_key:
                # Générer une nouvelle clé maître Fernet
                master_key = Fernet.generate_key().decode()
                
                # Stocker dans MinIO avec métadonnées
                success = self.key_store.store_key(
                    self.current_key_id, 
                    master_key,
                    {
                        'description': 'Master encryption key for toolbox',
                        'auto_generated': True,
                        'algorithm': 'Fernet-AES128',
                        'purpose': 'sensitive_data_encryption'
                    }
                )
                
                if success:
                    logger.info("🔑 Nouvelle clé maître générée et stockée dans MinIO")
                else:
                    logger.error("❌ Impossible de stocker la clé maître")
                    raise Exception("Failed to store master key")
            else:
                logger.info("🔑 Clé maître récupérée depuis MinIO")
                
        except Exception as e:
            logger.error(f"❌ Erreur initialisation clé maître: {e}")
            raise
    
    def get_current_encryption_key(self) -> str:
        """Retourne la clé de chiffrement active"""
        try:
            key = self.key_store.retrieve_key(self.current_key_id)
            if not key:
                logger.error("❌ Impossible de récupérer la clé de chiffrement")
                # Fallback : recréer une clé
                self._initialize_master_key()
                key = self.key_store.retrieve_key(self.current_key_id)
            
            return key
        except Exception as e:
            logger.error(f"❌ Erreur récupération clé: {e}")
            # Fallback de sécurité
            return Fernet.generate_key().decode()
    
    def generate_new_key(self, key_id: str = None, purpose: str = "general") -> str:
        """Génère une nouvelle clé de chiffrement"""
        try:
            if not key_id:
                key_id = f"key_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            new_key = Fernet.generate_key().decode()
            
            success = self.key_store.store_key(
                key_id, 
                new_key,
                {
                    'description': f'Generated key for {purpose}',
                    'algorithm': 'Fernet-AES128',
                    'purpose': purpose,
                    'generated_at': datetime.now().isoformat()
                }
            )
            
            if success:
                logger.info(f"🔑 Nouvelle clé générée: {key_id}")
                return new_key
            else:
                logger.error(f"❌ Erreur génération clé {key_id}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Erreur génération clé: {e}")
            return None
    
    def rotate_master_key(self) -> bool:
        """Rotation de la clé maître avec archivage sécurisé"""
        try:
            logger.info("🔄 Début rotation clé maître")
            
            # 1. Archiver l'ancienne clé
            old_key_archived = self.key_store.archive_key(self.current_key_id)
            if not old_key_archived:
                logger.error("❌ Impossible d'archiver l'ancienne clé")
                return False
            
            # 2. Générer et stocker la nouvelle clé
            new_key = Fernet.generate_key().decode()
            success = self.key_store.store_key(
                self.current_key_id, 
                new_key,
                {
                    'description': 'Rotated master encryption key',
                    'rotation_date': datetime.now().isoformat(),
                    'algorithm': 'Fernet-AES128',
                    'purpose': 'master_key_rotation'
                }
            )
            
            if success:
                logger.info("✅ Rotation clé maître terminée avec succès")
                return True
            else:
                logger.error("❌ Erreur lors de la rotation de clé")
                return False
                
        except Exception as e:
            logger.error(f"❌ Erreur rotation clé maître: {e}")
            return False
    
    def get_key_info(self) -> Dict:
        """Informations sur le système de clés"""
        try:
            keys = self.key_store.list_keys()
            master_key_info = next((k for k in keys if k['key_id'] == self.current_key_id), None)
            
            return {
                'current_key_id': self.current_key_id,
                'algorithm': 'Fernet (AES-128)',
                'storage': 'MinIO S3-compatible',
                'total_keys': len(keys),
                'master_key_info': master_key_info,
                'status': 'operational'
            }
        except Exception as e:
            logger.error(f"❌ Erreur récupération infos clés: {e}")
            return {
                'current_key_id': self.current_key_id,
                'algorithm': 'Fernet (AES-128)',
                'storage': 'MinIO S3-compatible',
                'status': 'error',
                'error': str(e)
            }
    
    def list_all_keys(self) -> List[Dict]:
        """Liste toutes les clés disponibles"""
        return self.key_store.list_keys()
    
    def archive_key(self, key_id: str) -> bool:
        """Archive une clé spécifique"""
        if key_id == self.current_key_id:
            logger.warning("⚠️ Tentative d'archivage de la clé maître - utilisez rotate_master_key()")
            return False
        
        return self.key_store.archive_key(key_id)
    
    def delete_key(self, key_id: str) -> bool:
        """Supprime définitivement une clé (admin seulement)"""
        if key_id == self.current_key_id:
            logger.error("❌ Impossible de supprimer la clé maître")
            return False
        
        return self.key_store.delete_key(key_id)
    
    def get_audit_logs(self, key_id: str = None, date: str = None) -> List[Dict]:
        """Récupère les logs d'audit des clés"""
        return self.key_store.get_audit_logs(key_id, date)
    
    def validate_key(self, key_data: str) -> bool:
        """Valide qu'une clé est un format Fernet valide"""
        try:
            Fernet(key_data.encode())
            return True
        except Exception:
            return False
    
    def get_status(self) -> Dict:
        """Statut complet du service de gestion des clés"""
        try:
            info = self.get_key_info()
            
            # Test de la clé active
            current_key = self.get_current_encryption_key()
            key_valid = self.validate_key(current_key) if current_key else False
            
            return {
                'service': 'KeyManagementService',
                'storage': 'MinIO',
                'operational': key_valid,
                'key_info': info,
                'last_check': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'service': 'KeyManagementService',
                'storage': 'MinIO',
                'operational': False,
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }

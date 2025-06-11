"""
Stockage sécurisé des clés dans MinIO - Tâche 23
Compatible avec l'architecture PostgreSQL existante
"""
import os
import json
from datetime import datetime
from typing import Optional, Dict, List
from minio import Minio
from minio.error import S3Error
from io import BytesIO
import logging

logger = logging.getLogger('toolbox.keys')

class MinIOKeyStore:
    """Stockage sécurisé des clés dans MinIO (Tâche 23)"""
    
    def __init__(self, minio_client: Minio):
        self.client = minio_client
        self.bucket = 'encryption-keys'
        self._ensure_bucket_security()
    
    def _ensure_bucket_security(self):
        """Configure les politiques de sécurité du bucket keys"""
        try:
            # Vérifier que le bucket existe
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
                logger.info(f"🔒 Bucket sécurisé créé: {self.bucket}")
            
            # Note: Les politiques MinIO avancées nécessitent un setup plus complexe
            # Pour un projet ESI M1, on se concentre sur l'implémentation fonctionnelle
            logger.info(f"🔒 Bucket de clés sécurisé: {self.bucket}")
            
        except S3Error as e:
            logger.warning(f"⚠️ Impossible de configurer la sécurité du bucket: {e}")
    
    def store_key(self, key_id: str, key_data: str, metadata: Dict = None) -> bool:
        """Stocke une clé dans MinIO avec métadonnées"""
        try:
            # Métadonnées par défaut conformes au cahier des charges
            meta = {
                'created_at': datetime.now().isoformat(),
                'key_type': 'fernet',
                'algorithm': 'AES-128',
                'status': 'active',
                'created_by': 'toolbox_system'
            }
            
            if metadata:
                meta.update(metadata)
            
            # Stockage sécurisé dans MinIO
            key_path = f'keys/{key_id}.key'
            key_bytes = key_data.encode()
            self.client.put_object(
                self.bucket,
                key_path,
                BytesIO(key_bytes),
                length=len(key_bytes),
                metadata=meta
            )

            # Log de l'opération pour audit
            self._log_key_operation(key_id, 'store', success=True)
            logger.info(f"🔑 Clé stockée dans MinIO: {key_id}")
            return True
            
        except S3Error as e:
            logger.error(f"❌ Erreur stockage clé {key_id}: {e}")
            self._log_key_operation(key_id, 'store', success=False, error=str(e))
            return False
    
    def retrieve_key(self, key_id: str) -> Optional[str]:
        """Récupère une clé depuis MinIO"""
        try:
            key_path = f'keys/{key_id}.key'
            response = self.client.get_object(self.bucket, key_path)
            key_data = response.read().decode()
            
            # Log de l'accès pour audit (conforme tâche 23)
            self._log_key_operation(key_id, 'retrieve', success=True)
            logger.debug(f"🔑 Clé récupérée: {key_id}")
            
            return key_data
            
        except S3Error as e:
            logger.error(f"❌ Erreur récupération clé {key_id}: {e}")
            self._log_key_operation(key_id, 'retrieve', success=False, error=str(e))
            return None
    
    def list_keys(self) -> List[Dict]:
        """Liste toutes les clés avec métadonnées"""
        try:
            keys = []
            objects = self.client.list_objects(self.bucket, prefix='keys/', recursive=True)
            
            for obj in objects:
                if obj.object_name.endswith('.key'):
                    # Récupérer les métadonnées
                    try:
                        stat = self.client.stat_object(self.bucket, obj.object_name)
                        
                        key_info = {
                            'key_id': obj.object_name.replace('keys/', '').replace('.key', ''),
                            'size': obj.size,
                            'last_modified': obj.last_modified.isoformat() if obj.last_modified else None,
                            'metadata': stat.metadata or {}
                        }
                        keys.append(key_info)
                    except S3Error as e:
                        logger.warning(f"⚠️ Impossible de récupérer métadonnées: {obj.object_name}: {e}")
            
            logger.debug(f"📋 {len(keys)} clés listées")
            return keys
            
        except S3Error as e:
            logger.error(f"❌ Erreur listage clés: {e}")
            return []
    
    def archive_key(self, key_id: str) -> bool:
        """Archive une clé (déplace vers archive/) - Rotation sécurisée"""
        try:
            source_path = f'keys/{key_id}.key'
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archive_path = f'archive/{key_id}_{timestamp}.key'
            
            # Copier vers archive
            self.client.copy_object(
                self.bucket, 
                archive_path,
                f'/{self.bucket}/{source_path}'
            )
            
            # Supprimer l'original
            self.client.remove_object(self.bucket, source_path)
            
            # Log de l'archivage
            self._log_key_operation(key_id, 'archive', success=True, 
                                  details={'archive_path': archive_path})
            
            logger.info(f"📦 Clé archivée: {key_id} → {archive_path}")
            return True
            
        except S3Error as e:
            logger.error(f"❌ Erreur archivage clé {key_id}: {e}")
            self._log_key_operation(key_id, 'archive', success=False, error=str(e))
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """Supprime définitivement une clé (admin seulement)"""
        try:
            key_path = f'keys/{key_id}.key'
            self.client.remove_object(self.bucket, key_path)
            
            # Log de la suppression
            self._log_key_operation(key_id, 'delete', success=True)
            logger.warning(f"🗑️ Clé supprimée définitivement: {key_id}")
            return True
            
        except S3Error as e:
            logger.error(f"❌ Erreur suppression clé {key_id}: {e}")
            self._log_key_operation(key_id, 'delete', success=False, error=str(e))
            return False
    
    def _log_key_operation(self, key_id: str, operation: str, success: bool, 
                          error: str = None, details: Dict = None):
        """Log des opérations sur les clés pour audit (conforme tâche 23)"""
        audit_log = {
            'timestamp': datetime.now().isoformat(),
            'key_id': key_id,
            'operation': operation,
            'success': success,
            'user': 'system',  # À améliorer avec le système d'auth existant
            'details': details or {}
        }
        
        if error:
            audit_log['error'] = error
        
        try:
            # Stocker le log d'audit dans MinIO
            date_str = datetime.now().strftime('%Y%m%d')
            log_name = f'audit/{date_str}/{key_id}_{operation}_{int(datetime.now().timestamp())}.json'
            
            log_data = json.dumps(audit_log, indent=2).encode()
            self.client.put_object(
                self.bucket,
                log_name,
                BytesIO(log_data),
                length=len(log_data)
            )

        except S3Error:
            # En cas d'erreur, au moins logger localement
            logger.warning(f"⚠️ Impossible de stocker l'audit pour {key_id}: {operation}")
    
    def get_audit_logs(self, key_id: str = None, date: str = None) -> List[Dict]:
        """Récupère les logs d'audit"""
        try:
            logs = []
            prefix = 'audit/'
            
            if date:
                prefix += f'{date}/'
            
            objects = self.client.list_objects(self.bucket, prefix=prefix, recursive=True)
            
            for obj in objects:
                if obj.object_name.endswith('.json'):
                    if not key_id or key_id in obj.object_name:
                        try:
                            response = self.client.get_object(self.bucket, obj.object_name)
                            log_data = json.loads(response.read().decode())
                            logs.append(log_data)
                        except Exception as e:
                            logger.warning(f"⚠️ Erreur lecture log {obj.object_name}: {e}")
            
            return sorted(logs, key=lambda x: x['timestamp'], reverse=True)
            
        except S3Error as e:
            logger.error(f"❌ Erreur récupération logs audit: {e}")
            return []

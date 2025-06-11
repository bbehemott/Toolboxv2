"""
Service de sauvegarde utilisant MinIO - Tâche 40
Compatible avec l'architecture Flask + PostgreSQL existante
"""
import os
import json
import tempfile
import subprocess
import tarfile
from datetime import datetime
from typing import Dict, List, Optional
from minio import Minio
from minio.error import S3Error
import logging

logger = logging.getLogger('toolbox.backup')

class BackupService:
    """Service de sauvegarde utilisant MinIO (CONFORME TÂCHE 40)"""
    
    def __init__(self, minio_client: Minio, db_manager=None):
        self.minio = minio_client
        self.db = db_manager
        self.backup_bucket = 'backups'
        self._ensure_backup_bucket()
    
    def _ensure_backup_bucket(self):
        """S'assure que le bucket de sauvegarde existe"""
        try:
            if not self.minio.bucket_exists(self.backup_bucket):
                self.minio.make_bucket(self.backup_bucket)
                logger.info(f"📦 Bucket de sauvegarde créé: {self.backup_bucket}")
        except S3Error as e:
            logger.error(f"❌ Erreur création bucket backup: {e}")
    
    def create_full_backup(self, description: str = "Automatic backup") -> Dict:
        """Sauvegarde complète : PostgreSQL + MinIO buckets + métadonnées"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_id = f"backup_{timestamp}"
        
        logger.info(f"🚀 Début sauvegarde complète: {backup_id}")
        
        try:
            backup_files = {}
            
            # 1. Sauvegarde PostgreSQL
            logger.info("📊 Sauvegarde base de données PostgreSQL...")
            db_backup = self._backup_postgresql(backup_id)
            if db_backup:
                backup_files['database'] = db_backup
            
            # 2. Sauvegarde des clés MinIO
            logger.info("🔐 Sauvegarde clés de chiffrement...")
            keys_backup = self._backup_encryption_keys(backup_id)
            if keys_backup:
                backup_files['encryption_keys'] = keys_backup
            
            # 3. Sauvegarde des preuves de scan
            logger.info("🔍 Sauvegarde preuves de scan...")
            evidences_backup = self._backup_scan_evidences(backup_id)
            if evidences_backup:
                backup_files['scan_evidences'] = evidences_backup
            
            # 4. Configuration de l'application
            logger.info("⚙️ Sauvegarde configuration...")
            config_backup = self._backup_application_config(backup_id)
            if config_backup:
                backup_files['application_config'] = config_backup
            
            # 5. Métadonnées de sauvegarde
            metadata = {
                'backup_id': backup_id,
                'timestamp': timestamp,
                'description': description,
                'files': backup_files,
                'version': '2.0',
                'created_by': 'BackupService',
                'status': 'completed',
                'toolbox_version': 'ESI_M1_Cyber'
            }
            
            # 6. Stocker les métadonnées
            self._store_backup_metadata(backup_id, metadata)
            
            logger.info(f"✅ Sauvegarde complète créée: {backup_id}")
            return {
                'success': True,
                'backup_id': backup_id,
                'metadata': metadata,
                'files_count': len(backup_files)
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde {backup_id}: {e}")
            return {
                'success': False,
                'backup_id': backup_id,
                'error': str(e)
            }
    
    def _backup_postgresql(self, backup_id: str) -> Optional[str]:
        """Sauvegarde PostgreSQL vers MinIO"""
        try:
            # Créer dump PostgreSQL
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.sql', delete=False) as f:
                temp_path = f.name
            
            # Commande pg_dump via Docker
            dump_command = [
                'pg_dump', 
                '-h', 'postgres', 
                '-U', 'toolbox_user', 
                '-d', 'toolbox'
            ]
            
            logger.debug(f"🔧 Exécution: {' '.join(dump_command)}")
            
            with open(temp_path, 'w') as f:
                result = subprocess.run(
                    dump_command,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300,
                    env=env
                )
            
            if result.returncode != 0:
                logger.error(f"❌ pg_dump failed: {result.stderr}")
                os.unlink(temp_path)
                return None
            
            # Upload vers MinIO
            backup_name = f"{backup_id}_database.sql"
            self.minio.fput_object(self.backup_bucket, backup_name, temp_path)
            
            # Nettoyer le fichier temporaire
            os.unlink(temp_path)
            
            logger.info(f"📊 Sauvegarde PostgreSQL terminée: {backup_name}")
            return backup_name
            
        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout lors de la sauvegarde PostgreSQL")
            return None
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde PostgreSQL: {e}")
            return None
    
    def _backup_encryption_keys(self, backup_id: str) -> Optional[str]:
        """Sauvegarde du bucket encryption-keys"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
                temp_path = f.name
            
            # Créer un répertoire temporaire pour télécharger les clés
            with tempfile.TemporaryDirectory() as temp_dir:
                keys_dir = os.path.join(temp_dir, 'encryption-keys')
                os.makedirs(keys_dir, exist_ok=True)
                
                # Télécharger tous les objets du bucket encryption-keys
                try:
                    objects = self.minio.list_objects('encryption-keys', recursive=True)
                    
                    for obj in objects:
                        local_path = os.path.join(keys_dir, obj.object_name)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        self.minio.fget_object('encryption-keys', obj.object_name, local_path)
                        logger.debug(f"📥 Clé téléchargée: {obj.object_name}")
                
                except S3Error as e:
                    if "NoSuchBucket" in str(e):
                        logger.warning("⚠️ Bucket encryption-keys n'existe pas encore")
                        # Créer un fichier vide pour indiquer l'absence de clés
                        with open(os.path.join(keys_dir, 'no_keys.txt'), 'w') as f:
                            f.write("No encryption keys found at backup time\n")
                    else:
                        raise
                
                # Créer l'archive tar.gz
                with tarfile.open(temp_path, 'w:gz') as tar:
                    tar.add(keys_dir, arcname='encryption-keys')
            
            # Upload vers MinIO
            backup_name = f"{backup_id}_keys.tar.gz"
            self.minio.fput_object(self.backup_bucket, backup_name, temp_path)
            
            # Nettoyer
            os.unlink(temp_path)
            
            logger.info(f"🔐 Sauvegarde clés terminée: {backup_name}")
            return backup_name
            
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde clés: {e}")
            return None
    
    def _backup_scan_evidences(self, backup_id: str) -> Optional[str]:
        """Sauvegarde du bucket scan-evidences"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
                temp_path = f.name
            
            with tempfile.TemporaryDirectory() as temp_dir:
                evidences_dir = os.path.join(temp_dir, 'scan-evidences')
                os.makedirs(evidences_dir, exist_ok=True)
                
                try:
                    objects = self.minio.list_objects('scan-evidences', recursive=True)
                    
                    for obj in objects:
                        local_path = os.path.join(evidences_dir, obj.object_name)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        self.minio.fget_object('scan-evidences', obj.object_name, local_path)
                
                except S3Error as e:
                    if "NoSuchBucket" in str(e):
                        logger.warning("⚠️ Bucket scan-evidences n'existe pas encore")
                        with open(os.path.join(evidences_dir, 'no_evidences.txt'), 'w') as f:
                            f.write("No scan evidences found at backup time\n")
                    else:
                        raise
                
                # Créer l'archive
                with tarfile.open(temp_path, 'w:gz') as tar:
                    tar.add(evidences_dir, arcname='scan-evidences')
            
            # Upload vers MinIO
            backup_name = f"{backup_id}_evidences.tar.gz"
            self.minio.fput_object(self.backup_bucket, backup_name, temp_path)
            
            os.unlink(temp_path)
            
            logger.info(f"🔍 Sauvegarde preuves terminée: {backup_name}")
            return backup_name
            
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde preuves: {e}")
            return None
    
    def _backup_application_config(self, backup_id: str) -> Optional[str]:
        """Sauvegarde configuration de l'application"""
        try:
            config_data = {
                'backup_timestamp': datetime.now().isoformat(),
                'docker_compose_services': [
                    'app', 'worker', 'postgres', 'redis', 'minio', 'graylog'
                ],
                'environment_variables': [
                    'FLASK_ENV', 'DB_HOST', 'DB_NAME', 'MINIO_ENDPOINT'
                ],
                'notes': 'Configuration backup for ESI M1 Cyber toolbox'
            }
            
            config_json = json.dumps(config_data, indent=2)
            backup_name = f"{backup_id}_config.json"
            
            self.minio.put_object(
                self.backup_bucket,
                backup_name,
                config_json.encode(),
                len(config_json.encode())
            )
            
            logger.info(f"⚙️ Sauvegarde config terminée: {backup_name}")
            return backup_name
            
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde config: {e}")
            return None
    
    def _store_backup_metadata(self, backup_id: str, metadata: Dict):
        """Stocke les métadonnées de sauvegarde"""
        try:
            metadata_name = f"{backup_id}_metadata.json"
            metadata_json = json.dumps(metadata, indent=2)
            
            from io import BytesIO
            metadata_bytes = metadata_json.encode()
            self.minio.put_object(
                self.backup_bucket,
                metadata_name,
                BytesIO(metadata_bytes),
                len(metadata_bytes)
            )
            
            logger.debug(f"📝 Métadonnées stockées: {metadata_name}")
            
        except Exception as e:
            logger.error(f"❌ Erreur stockage métadonnées: {e}")

    def list_backups(self) -> List[Dict]:
        """Liste toutes les sauvegardes disponibles"""
        try:
            backups = []
            objects = self.minio.list_objects(self.backup_bucket, recursive=True)
            metadata_objects = [obj for obj in objects if obj.object_name.endswith('_metadata.json')]

            for obj in metadata_objects:
                try:

                    response = self.minio.get_object(self.backup_bucket, obj.object_name)
                    metadata = json.loads(response.read().decode())

                    backup_info = {
                        'backup_id': metadata['backup_id'],
                        'timestamp': metadata['timestamp'],
                        'description': metadata.get('description', 'No description'),
                        'size': obj.size,
                        'status': metadata.get('status', 'unknown'),
                        'files_count': len(metadata.get('files', {})),
                        'version': metadata.get('version', '1.0')
                    }
                    backups.append(backup_info)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Erreur lecture backup {obj.object_name}: {e}")
            
            return sorted(backups, key=lambda x: x['timestamp'], reverse=True)
            
        except Exception as e:
            logger.error(f"❌ Erreur listage sauvegardes: {e}")
            return []

    def get_backup_details(self, backup_id: str) -> Optional[Dict]:
        """Récupère les détails d'une sauvegarde"""
        try:
            metadata_name = f"{backup_id}_metadata.json"
            response = self.minio.get_object(self.backup_bucket, metadata_name)
            metadata = json.loads(response.read().decode())
            
            return metadata
            
        except Exception as e:
            logger.error(f"❌ Erreur récupération détails backup {backup_id}: {e}")
            return None
    
    def delete_backup(self, backup_id: str) -> bool:
        """Supprime une sauvegarde complète"""
        try:
            # Récupérer les métadonnées pour connaître les fichiers
            metadata = self.get_backup_details(backup_id)
            if not metadata:
                logger.error(f"❌ Backup {backup_id} non trouvé")
                return False
            
            # Supprimer tous les fichiers de la sauvegarde
            files_to_delete = list(metadata.get('files', {}).values())
            files_to_delete.append(f"{backup_id}_metadata.json")
            
            for file_name in files_to_delete:
                try:
                    self.minio.remove_object(self.backup_bucket, file_name)
                    logger.debug(f"🗑️ Fichier supprimé: {file_name}")
                except S3Error as e:
                    logger.warning(f"⚠️ Impossible de supprimer {file_name}: {e}")
            
            logger.info(f"🗑️ Sauvegarde supprimée: {backup_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur suppression backup {backup_id}: {e}")
            return False
    
    def get_backup_size(self, backup_id: str) -> int:
        """Calcule la taille totale d'une sauvegarde"""
        try:
            metadata = self.get_backup_details(backup_id)
            if not metadata:
                return 0
            
            total_size = 0
            files_to_check = list(metadata.get('files', {}).values())
            files_to_check.append(f"{backup_id}_metadata.json")
            
            for file_name in files_to_check:
                try:
                    stat = self.minio.stat_object(self.backup_bucket, file_name)
                    total_size += stat.size
                except S3Error:
                    pass
            
            return total_size
            
        except Exception as e:
            logger.error(f"❌ Erreur calcul taille backup {backup_id}: {e}")
            return 0
    
    def restore_backup(self, backup_id: str) -> Dict:
        """Restaure une sauvegarde complète"""
        logger.info(f"🔄 Début restauration: {backup_id}")
        
        try:
            # Récupérer les métadonnées
            metadata = self.get_backup_details(backup_id)
            if not metadata:
                return {'success': False, 'error': f'Backup {backup_id} not found'}
            
            results = {}
            
            # 1. Restaurer PostgreSQL
            if 'database' in metadata.get('files', {}):
                logger.info("📊 Restauration base de données...")
                db_restored = self._restore_postgresql(backup_id, metadata['files']['database'])
                results['database'] = db_restored
            
            # 2. Restaurer les clés
            if 'encryption_keys' in metadata.get('files', {}):
                logger.info("🔐 Restauration clés de chiffrement...")
                keys_restored = self._restore_encryption_keys(backup_id, metadata['files']['encryption_keys'])
                results['encryption_keys'] = keys_restored
            
            # 3. Restaurer les preuves
            if 'scan_evidences' in metadata.get('files', {}):
                logger.info("🔍 Restauration preuves de scan...")
                evidences_restored = self._restore_scan_evidences(backup_id, metadata['files']['scan_evidences'])
                results['scan_evidences'] = evidences_restored
            
            # Vérifier le succès global
            success = all(results.values())
            
            if success:
                logger.info(f"✅ Restauration complète terminée: {backup_id}")
            else:
                logger.warning(f"⚠️ Restauration partielle: {backup_id}")
            
            return {
                'success': success,
                'backup_id': backup_id,
                'results': results,
                'restored_components': list(results.keys())
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur restauration {backup_id}: {e}")
            return {'success': False, 'backup_id': backup_id, 'error': str(e)}
    
    def _restore_postgresql(self, backup_id: str, backup_file: str) -> bool:
        """Restaure PostgreSQL depuis MinIO"""
        try:
            # Télécharger depuis MinIO
            with tempfile.NamedTemporaryFile(suffix='.sql', delete=False) as f:
                temp_path = f.name
            
            self.minio.fget_object(self.backup_bucket, backup_file, temp_path)
            
            # Restaurer dans PostgreSQL
            restore_command = [
                'docker', 'exec', '-i', 'toolbox-postgres',
                'psql', '-U', 'toolbox_user', '-d', 'toolbox'
            ]
            
            with open(temp_path, 'r') as f:
                result = subprocess.run(
                    restore_command, 
                    stdin=f, 
                    stderr=subprocess.PIPE, 
                    text=True,
                    timeout=300
                )
            
            # Nettoyer
            os.unlink(temp_path)
            
            if result.returncode == 0:
                logger.info(f"📊 PostgreSQL restauré: {backup_file}")
                return True
            else:
                logger.error(f"❌ Erreur restauration PostgreSQL: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout lors de la restauration PostgreSQL")
            return False
        except Exception as e:
            logger.error(f"❌ Erreur restauration PostgreSQL: {e}")
            return False
    
    def _restore_encryption_keys(self, backup_id: str, backup_file: str) -> bool:
        """Restaure les clés depuis MinIO"""
        try:
            # Télécharger l'archive
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
                temp_path = f.name
            
            self.minio.fget_object(self.backup_bucket, backup_file, temp_path)
            
            # Extraire et restaurer dans MinIO
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extraire l'archive
                with tarfile.open(temp_path, 'r:gz') as tar:
                    tar.extractall(temp_dir)
                
                # Re-uploader dans le bucket encryption-keys
                keys_dir = os.path.join(temp_dir, 'encryption-keys')
                if os.path.exists(keys_dir):
                    for root, dirs, files in os.walk(keys_dir):
                        for file in files:
                            if file == 'no_keys.txt':
                                continue
                            
                            local_path = os.path.join(root, file)
                            object_name = os.path.relpath(local_path, keys_dir)
                            
                            self.minio.fput_object('encryption-keys', object_name, local_path)
                            logger.debug(f"📤 Clé restaurée: {object_name}")
            
            # Nettoyer
            os.unlink(temp_path)
            
            logger.info(f"🔐 Clés restaurées: {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur restauration clés: {e}")
            return False
    
    def _restore_scan_evidences(self, backup_id: str, backup_file: str) -> bool:
        """Restaure les preuves de scan depuis MinIO"""
        try:
            # Télécharger l'archive
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
                temp_path = f.name
            
            self.minio.fget_object(self.backup_bucket, backup_file, temp_path)
            
            # Extraire et restaurer
            with tempfile.TemporaryDirectory() as temp_dir:
                with tarfile.open(temp_path, 'r:gz') as tar:
                    tar.extractall(temp_dir)
                
                evidences_dir = os.path.join(temp_dir, 'scan-evidences')
                if os.path.exists(evidences_dir):
                    for root, dirs, files in os.walk(evidences_dir):
                        for file in files:
                            if file == 'no_evidences.txt':
                                continue
                            
                            local_path = os.path.join(root, file)
                            object_name = os.path.relpath(local_path, evidences_dir)
                            
                            self.minio.fput_object('scan-evidences', object_name, local_path)
                            logger.debug(f"📤 Preuve restaurée: {object_name}")
            
            os.unlink(temp_path)
            
            logger.info(f"🔍 Preuves restaurées: {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur restauration preuves: {e}")
            return False
    
    def get_storage_stats(self) -> Dict:
        """Statistiques de stockage des sauvegardes"""
        try:
            backups = self.list_backups()
            
            total_size = 0
            for backup in backups:
                total_size += self.get_backup_size(backup['backup_id'])
            
            return {
                'total_backups': len(backups),
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'average_size_mb': round(total_size / (1024 * 1024) / len(backups), 2) if backups else 0,
                'oldest_backup': min(backups, key=lambda x: x['timestamp'])['timestamp'] if backups else None,
                'newest_backup': max(backups, key=lambda x: x['timestamp'])['timestamp'] if backups else None
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur stats stockage: {e}")
            return {
                'total_backups': 0,
                'total_size_bytes': 0,
                'error': str(e)
            }

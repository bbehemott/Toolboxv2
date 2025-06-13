"""
Gestionnaire sécurisé des fichiers PCAP
"""

import os
import shutil
from pathlib import Path
import uuid
from security import MinIOClient

class PcapFileManager:
    """Gestionnaire des fichiers PCAP avec sécurité"""
    
    def __init__(self):
        self.pcap_dir = Path("/app/data/pcap")
        self.pcap_dir.mkdir(exist_ok=True)
        
        # Utiliser MinIO si disponible (comme dans votre toolbox)
        try:
            self.minio_client = MinIOClient()
            self.use_minio = self.minio_client.is_available()
        except:
            self.use_minio = False
    
    def save_pcap(self, pcap_content, filename_prefix="capture"):
        """Sauvegarder fichier PCAP de manière sécurisée"""
        
        # Générer nom unique
        unique_id = str(uuid.uuid4())[:8]
        safe_filename = f"{filename_prefix}_{unique_id}.pcap"
        
        if self.use_minio:
            # Stocker dans MinIO (sécurisé)
            try:
                self.minio_client.upload_file(
                    bucket="pcap-files",
                    object_name=safe_filename,
                    file_path=pcap_content
                )
                return f"minio://{safe_filename}"
            except Exception as e:
                logger.warning(f"MinIO échec, fallback local: {e}")
        
        # Fallback : stockage local
        local_path = self.pcap_dir / safe_filename
        shutil.copy2(pcap_content, local_path)
        os.chmod(local_path, 0o644)  # Permissions lecture
        
        return str(local_path)
    
    def get_pcap(self, pcap_reference):
        """Récupérer fichier PCAP de manière sécurisée"""
        
        if pcap_reference.startswith("minio://"):
            # Télécharger depuis MinIO
            object_name = pcap_reference.replace("minio://", "")
            temp_path = f"/tmp/{object_name}"
            
            try:
                self.minio_client.download_file(
                    bucket="pcap-files",
                    object_name=object_name,
                    file_path=temp_path
                )
                return temp_path
            except Exception as e:
                logger.error(f"Erreur téléchargement MinIO: {e}")
                return None
        
        # Fichier local - vérifier sécurité
        if not pcap_reference.startswith("/app/data/pcap/"):
            logger.warning(f"Accès PCAP non autorisé: {pcap_reference}")
            return None
        
        if os.path.exists(pcap_reference):
            return pcap_reference
        
        return None
    
    def list_user_pcaps(self, user_id):
        """Lister les PCAP d'un utilisateur"""
        # Récupérer depuis BDD les PCAP de l'utilisateur
        db = DatabaseManager()
        results = db.get_user_traffic_results(user_id)
        
        pcaps = []
        for result in results:
            if result['pcap_file']:
                pcaps.append({
                    'file': result['pcap_file'],
                    'target': result['target'],
                    'created_at': result['created_at'],
                    'task_type': result['task_type']
                })
        
        return pcaps

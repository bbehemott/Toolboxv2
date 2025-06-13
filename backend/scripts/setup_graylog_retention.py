#!/usr/bin/env python3
"""
Script de correction pour la configuration Graylog
Corrige les erreurs de l'API Graylog 4.3
"""

import requests
import json
import time
import os
from requests.auth import HTTPBasicAuth

class GraylogFixManager:
    def __init__(self, graylog_url="http://localhost:9000", username="admin", password="admin"):
        self.base_url = graylog_url
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {
            'Content-Type': 'application/json',
            'X-Requested-By': 'python-script'
        }
    
    def get_default_index_set(self):
        """Récupérer l'index set par défaut"""
        try:
            response = requests.get(
                f"{self.base_url}/api/system/indices/index_sets",
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code == 200:
                index_sets = response.json()
                for index_set in index_sets.get('index_sets', []):
                    if index_set.get('default', False):
                        return index_set
                
                # Si pas de défaut, prendre le premier
                if index_sets.get('index_sets'):
                    return index_sets['index_sets'][0]
            
            return None
        except Exception as e:
            print(f"❌ Erreur récupération index sets: {e}")
            return None
    
    def create_streams_fixed(self):
        """Créer des streams avec configuration correcte"""
        print("📊 Création des streams corrigés...")
        
        # Récupérer l'index set par défaut
        default_index_set = self.get_default_index_set()
        if not default_index_set:
            print("❌ Impossible de récupérer l'index set par défaut")
            return []
        
        index_set_id = default_index_set.get('id')
        
        tools_streams = [
            {
                "title": "Toolbox Nmap Scans",
                "description": "Logs des scans Nmap de la toolbox",
                "matching_type": "AND",
                "index_set_id": index_set_id,
                "rules": [
                    {
                        "field": "application_name",
                        "type": 1,  # MATCH_EXACTLY
                        "value": "nmap",
                        "inverted": False
                    }
                ]
            },
            {
                "title": "Toolbox Burp Suite",
                "description": "Logs de Burp Suite",
                "matching_type": "AND",
                "index_set_id": index_set_id,
                "rules": [
                    {
                        "field": "application_name",
                        "type": 1,
                        "value": "burpsuite",
                        "inverted": False
                    }
                ]
            },
            {
                "title": "Toolbox OWASP ZAP",
                "description": "Logs d'OWASP ZAP",
                "matching_type": "AND",
                "index_set_id": index_set_id,
                "rules": [
                    {
                        "field": "application_name",
                        "type": 1,
                        "value": "zap",
                        "inverted": False
                    }
                ]
            },
            {
                "title": "Toolbox Metasploit",
                "description": "Logs de Metasploit Framework",
                "matching_type": "AND",
                "index_set_id": index_set_id,
                "rules": [
                    {
                        "field": "application_name",
                        "type": 1,
                        "value": "metasploit",
                        "inverted": False
                    }
                ]
            },
            {
                "title": "Toolbox Workers",
                "description": "Logs des workers Celery",
                "matching_type": "AND",
                "index_set_id": index_set_id,
                "rules": [
                    {
                        "field": "container_name",
                        "type": 2,  # MATCH_REGEX
                        "value": ".*worker.*",
                        "inverted": False
                    }
                ]
            }
        ]
        
        created_streams = []
        
        for stream_config in tools_streams:
            try:
                # Créer le stream
                response = requests.post(
                    f"{self.base_url}/api/streams",
                    json=stream_config,
                    auth=self.auth,
                    headers=self.headers
                )
                
                if response.status_code in [200, 201]:
                    stream_data = response.json()
                    stream_id = stream_data.get('stream_id')
                    
                    # Démarrer le stream
                    start_response = requests.post(
                        f"{self.base_url}/api/streams/{stream_id}/resume",
                        auth=self.auth,
                        headers=self.headers
                    )
                    
                    if start_response.status_code in [200, 204]:
                        print(f"✅ Stream '{stream_config['title']}' créé et démarré")
                        created_streams.append(stream_data)
                    else:
                        print(f"⚠️ Stream '{stream_config['title']}' créé mais pas démarré")
                        created_streams.append(stream_data)
                        
                else:
                    print(f"❌ Erreur création stream '{stream_config['title']}': {response.status_code}")
                    print(f"   Réponse: {response.text}")
                    
            except Exception as e:
                print(f"❌ Exception pour stream '{stream_config['title']}': {e}")
        
        return created_streams
    
    def update_retention_settings(self):
        """Mettre à jour les paramètres de rétention de l'index set par défaut"""
        print("🔧 Mise à jour des paramètres de rétention...")
        
        default_index_set = self.get_default_index_set()
        if not default_index_set:
            print("❌ Impossible de récupérer l'index set par défaut")
            return False
        
        index_set_id = default_index_set.get('id')
        
        # Configuration de rétention pour toolbox pentest
        retention_config = {
            "title": default_index_set.get('title', 'Default Index Set'),
            "description": "Index set avec rétention optimisée pour toolbox pentest",
            "index_prefix": default_index_set.get('index_prefix'),
            "shards": default_index_set.get('shards', 4),
            "replicas": default_index_set.get('replicas', 0),
            "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.SizeBasedRotationStrategy",
            "rotation_strategy": {
                "type": "org.graylog2.indexer.rotation.strategies.SizeBasedRotationStrategyConfig",
                "max_size": 1073741824  # 1GB
            },
            "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
            "retention_strategy": {
                "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
                "max_number_of_indices": 30  # 30 index = ~30GB max
            },
            "creation_date": default_index_set.get('creation_date'),
            "index_analyzer": default_index_set.get('index_analyzer', 'standard'),
            "index_template_name": default_index_set.get('index_template_name'),
            "index_optimization_max_num_segments": 1,
            "index_optimization_disabled": False,
            "field_type_refresh_interval": 5000,
            "writable": True,
            "default": default_index_set.get('default', False)
        }
        
        try:
            response = requests.put(
                f"{self.base_url}/api/system/indices/index_sets/{index_set_id}",
                json=retention_config,
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code in [200, 202]:
                print("✅ Paramètres de rétention mis à jour")
                return True
            else:
                print(f"❌ Erreur mise à jour rétention: {response.status_code}")
                print(f"   Réponse: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Exception mise à jour rétention: {e}")
            return False
    
    def verify_gelf_input(self):
        """Vérifier que l'input GELF fonctionne"""
        print("🔌 Vérification de l'input GELF...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/system/inputs",
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code == 200:
                inputs = response.json()
                gelf_inputs = [
                    inp for inp in inputs.get('inputs', [])
                    if 'GELF' in inp.get('type', '') and inp.get('attributes', {}).get('port') == 12201
                ]
                
                if gelf_inputs:
                    print(f"✅ {len(gelf_inputs)} input(s) GELF trouvé(s) sur port 12201")
                    for inp in gelf_inputs:
                        print(f"   - {inp.get('title', 'Sans nom')} ({inp.get('id')})")
                    return True
                else:
                    print("⚠️ Aucun input GELF trouvé sur le port 12201")
                    return False
            else:
                print(f"❌ Erreur récupération inputs: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Exception vérification GELF: {e}")
            return False
    
    def show_system_info(self):
        """Afficher les informations système Graylog"""
        print("📋 Informations système Graylog:")
        print("-" * 40)
        
        try:
            # Info système
            response = requests.get(
                f"{self.base_url}/api/system",
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code == 200:
                system_info = response.json()
                print(f"Version: {system_info.get('version', 'N/A')}")
                print(f"Timezone: {system_info.get('timezone', 'N/A')}")
                print(f"Operating System: {system_info.get('operating_system', 'N/A')}")
            
            # Statistiques des messages
            stats_response = requests.get(
                f"{self.base_url}/api/count/total",
                auth=self.auth,
                headers=self.headers
            )
            
            if stats_response.status_code == 200:
                stats = stats_response.json()
                print(f"Messages totaux: {stats.get('events', 0)}")
            
        except Exception as e:
            print(f"❌ Erreur récupération infos système: {e}")

def main():
    """Fonction principale de correction"""
    print("🔧 Script de correction Graylog pour la toolbox")
    print("=" * 50)
    
    manager = GraylogFixManager()
    
    # Afficher les infos système
    manager.show_system_info()
    
    print("\n🔄 Application des corrections...")
    
    # 1. Mettre à jour la rétention
    retention_ok = manager.update_retention_settings()
    
    # 2. Créer les streams corrigés
    streams = manager.create_streams_fixed()
    
    # 3. Vérifier l'input GELF
    gelf_ok = manager.verify_gelf_input()
    
    print("\n" + "=" * 50)
    print("📊 Résumé des corrections:")
    print(f"✅ Rétention: {'OK' if retention_ok else 'ÉCHEC'}")
    print(f"✅ Streams: {len(streams)} créé(s)")
    print(f"✅ Input GELF: {'OK' if gelf_ok else 'VÉRIFIER'}")
    
    print("\n🎯 Prochaines étapes:")
    print("1. Accédez à http://localhost:9000")
    print("2. Vérifiez les streams dans System/Streams")
    print("3. Vérifiez les inputs dans System/Inputs")
    print("4. Testez l'envoi de logs GELF vers le port 12201")
    
    return retention_ok and len(streams) > 0 and gelf_ok

if __name__ == "__main__":
    main()

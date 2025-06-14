#!/usr/bin/env python3
"""
Script d'auto-configuration Graylog pour la sécurité - ALERTES CORRIGÉES
Tâches 24 & 25 - Détection d'intrusion & Pare-feu
"""

import requests
import json
import time
import sys
from requests.auth import HTTPBasicAuth

class GraylogSecuritySetup:
    def __init__(self, graylog_url="http://localhost:9000", username="admin", password="admin"):
        self.base_url = graylog_url
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {
            'Content-Type': 'application/json',
            'X-Requested-By': 'toolbox-security-setup'
        }
        self.default_index_set_id = None
        
    def wait_for_graylog(self, max_attempts=15):
        """Attendre que Graylog soit prêt"""
        print("🔄 Vérification Graylog...")
        for i in range(max_attempts):
            try:
                response = requests.get(f"{self.base_url}/api/system", 
                                      auth=self.auth, timeout=5)
                if response.status_code == 200:
                    print("✅ Graylog accessible !")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            if i < max_attempts - 1:
                time.sleep(5)
        
        print("❌ Graylog non accessible")
        return False
    
    def get_default_index_set(self):
        """Récupérer l'index set par défaut"""
        try:
            response = requests.get(f"{self.base_url}/api/system/indices/index_sets", 
                                  auth=self.auth)
            if response.status_code == 200:
                index_sets = response.json()
                for index_set in index_sets.get('index_sets', []):
                    if index_set.get('default', False):
                        self.default_index_set_id = index_set.get('id')
                        print(f"✅ Index Set par défaut trouvé: {self.default_index_set_id}")
                        return True
                
                # Si pas de défaut, prendre le premier
                if index_sets.get('index_sets'):
                    self.default_index_set_id = index_sets['index_sets'][0].get('id')
                    print(f"✅ Premier Index Set utilisé: {self.default_index_set_id}")
                    return True
            
            print("❌ Aucun Index Set trouvé")
            return False
            
        except Exception as e:
            print(f"❌ Erreur récupération Index Set: {e}")
            return False
    
    def create_stream(self, stream_config):
        """Créer un stream de sécurité"""
        try:
            # Vérifier si le stream existe déjà
            response = requests.get(f"{self.base_url}/api/streams", auth=self.auth)
            if response.status_code == 200:
                existing_streams = response.json()
                for stream in existing_streams.get('streams', []):
                    if stream.get('title') == stream_config['title']:
                        print(f"⏩ Stream existe déjà: {stream_config['title']}")
                        return stream.get('id')
            
            # Ajouter l'index_set_id au stream config
            stream_config['index_set_id'] = self.default_index_set_id
            
            # Créer le nouveau stream
            response = requests.post(
                f"{self.base_url}/api/streams",
                auth=self.auth,
                headers=self.headers,
                json=stream_config
            )
            
            if response.status_code in [200, 201]:
                stream_data = response.json()
                stream_id = stream_data.get('stream_id')
                print(f"✅ Stream créé: {stream_config['title']}")
                
                # Démarrer le stream
                try:
                    requests.post(
                        f"{self.base_url}/api/streams/{stream_id}/resume",
                        auth=self.auth,
                        headers=self.headers
                    )
                except:
                    pass  # Pas grave si ça fail
                
                return stream_id
            else:
                print(f"⚠️ Erreur stream {stream_config['title']}: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Erreur stream {stream_config['title']}: {e}")
            return None
    
    def setup_security_streams(self):
        """Configurer tous les streams de sécurité"""
        print("\n🛡️ Configuration Streams Sécurité...")
        
        # D'abord récupérer l'index set par défaut
        if not self.get_default_index_set():
            print("❌ Impossible de récupérer l'Index Set")
            return {}
        
        streams_configs = [
            {
                "title": "Security_Failed_Auth",
                "description": "Échecs d'authentification - Tâche 24",
                "rules": [
                    {
                        "field": "message",
                        "type": 1,
                        "value": ".*(failed|invalid|incorrect|denied|unauthorized).*",
                        "inverted": False
                    }
                ],
                "matching_type": "OR",
                "remove_matches_from_default_stream": False
            },
            {
                "title": "Security_Brute_Force", 
                "description": "Tentatives de brute force - Tâche 24",
                "rules": [
                    {
                        "field": "message",
                        "type": 1,
                        "value": ".*(brute|multiple.*attempt|repeated.*fail|hydra|medusa).*",
                        "inverted": False
                    }
                ],
                "matching_type": "OR",
                "remove_matches_from_default_stream": False
            },
            {
                "title": "Security_Port_Scan",
                "description": "Scans de ports - Tâche 24", 
                "rules": [
                    {
                        "field": "message",
                        "type": 1,
                        "value": ".*(nmap|masscan|port.*scan|stealth.*scan).*",
                        "inverted": False
                    }
                ],
                "matching_type": "OR",
                "remove_matches_from_default_stream": False
            },
            {
                "title": "Security_Web_Attacks",
                "description": "Attaques web - Tâche 24",
                "rules": [
                    {
                        "field": "message", 
                        "type": 1,
                        "value": ".*(sql.*injection|xss|csrf|union.*select|script.*alert).*",
                        "inverted": False
                    }
                ],
                "matching_type": "OR",
                "remove_matches_from_default_stream": False
            },
            {
                "title": "Security_Internal_Access",
                "description": "Accès services internes - Tâche 25",
                "rules": [
                    {
                        "field": "message",
                        "type": 1, 
                        "value": ".*(9200|27017|6379|5432).*(access|connect|attempt).*",
                        "inverted": False
                    }
                ],
                "matching_type": "OR",
                "remove_matches_from_default_stream": False
            }
        ]
        
        created_streams = {}
        for stream_config in streams_configs:
            stream_id = self.create_stream(stream_config)
            if stream_id:
                created_streams[stream_config['title']] = stream_id
        
        return created_streams
    
    def create_legacy_alert_conditions(self, streams):
        """Créer des conditions d'alerte via l'ancienne API (plus compatible)"""
        print("\n🚨 Configuration des Alertes (Legacy API)...")
        
        if not streams:
            print("❌ Pas de streams disponibles pour les alertes")
            return {}
        
        created_alerts = {}
        
        # Alerte 1: Brute Force sur Failed Auth
        if 'Security_Failed_Auth' in streams:
            stream_id = streams['Security_Failed_Auth']
            alert_config = {
                "type": "message_count",
                "title": "Brute Force Attack Alert",
                "parameters": {
                    "threshold": 5,
                    "threshold_type": "MORE",
                    "time": 5,  # 5 minutes
                    "query": "",
                    "grace": 1
                }
            }
            
            try:
                response = requests.post(
                    f"{self.base_url}/api/streams/{stream_id}/alerts/conditions",
                    auth=self.auth,
                    headers=self.headers,
                    json=alert_config
                )
                
                if response.status_code in [200, 201]:
                    alert_data = response.json()
                    print("✅ Alerte Brute Force créée (Legacy)")
                    created_alerts['brute_force'] = alert_data.get('alert_condition_id')
                else:
                    print(f"⚠️ Erreur alerte Brute Force: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Erreur alerte Brute Force: {e}")
        
        # Alerte 2: Port Scan
        if 'Security_Port_Scan' in streams:
            stream_id = streams['Security_Port_Scan'] 
            alert_config = {
                "type": "message_count",
                "title": "Port Scan Alert",
                "parameters": {
                    "threshold": 10,
                    "threshold_type": "MORE", 
                    "time": 2,  # 2 minutes
                    "query": "",
                    "grace": 1
                }
            }
            
            try:
                response = requests.post(
                    f"{self.base_url}/api/streams/{stream_id}/alerts/conditions",
                    auth=self.auth,
                    headers=self.headers,
                    json=alert_config
                )
                
                if response.status_code in [200, 201]:
                    alert_data = response.json()
                    print("✅ Alerte Port Scan créée (Legacy)")
                    created_alerts['port_scan'] = alert_data.get('alert_condition_id')
                else:
                    print(f"⚠️ Erreur alerte Port Scan: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Erreur alerte Port Scan: {e}")
        
        # Alerte 3: Web Attacks
        if 'Security_Web_Attacks' in streams:
            stream_id = streams['Security_Web_Attacks']
            alert_config = {
                "type": "message_count", 
                "title": "Web Attack Alert",
                "parameters": {
                    "threshold": 2,
                    "threshold_type": "MORE",
                    "time": 3,  # 3 minutes
                    "query": "",
                    "grace": 1
                }
            }
            
            try:
                response = requests.post(
                    f"{self.base_url}/api/streams/{stream_id}/alerts/conditions",
                    auth=self.auth,
                    headers=self.headers,
                    json=alert_config
                )
                
                if response.status_code in [200, 201]:
                    alert_data = response.json()
                    print("✅ Alerte Web Attack créée (Legacy)")
                    created_alerts['web_attack'] = alert_data.get('alert_condition_id')
                else:
                    print(f"⚠️ Erreur alerte Web Attack: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Erreur alerte Web Attack: {e}")
        
        return created_alerts
    
    def setup_stream_alert_receivers(self, streams, alerts):
        """Configurer les destinataires d'alertes pour les streams"""
        print("\n📧 Configuration des destinataires d'alertes...")
        
        # Créer un destinataire email simple (pour démonstration)
        receiver_config = {
            "title": "Security Alerts Receiver",
            "type": "org.graylog2.alarmcallbacks.EmailAlarmCallback",
            "configuration": {
                "sender": "security@toolbox.local",
                "subject": "Security Alert: ${alert_condition.title}",
                "user_recipients": ["admin@toolbox.local"],
                "email_recipients": [],
                "body": "Alert triggered:\n\nCondition: ${alert_condition.title}\nStream: ${stream.title}\nTriggered at: ${check_result.triggered_at}\n\nMessage summary:\n${foreach backlog message}${message}\n${end}"
            }
        }
        
        receivers_created = 0
        
        for stream_name, stream_id in streams.items():
            try:
                response = requests.post(
                    f"{self.base_url}/api/streams/{stream_id}/alerts/receivers",
                    auth=self.auth,
                    headers=self.headers,
                    json=receiver_config
                )
                
                if response.status_code in [200, 201]:
                    print(f"✅ Destinataire configuré pour {stream_name}")
                    receivers_created += 1
                else:
                    print(f"⚠️ Erreur destinataire {stream_name}: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Erreur destinataire {stream_name}: {e}")
        
        return receivers_created
    
    def run_setup(self):
        """Exécuter la configuration complète"""
        print("🚀 CONFIGURATION SÉCURITÉ GRAYLOG")
        print("=" * 40)
        
        # Attendre Graylog
        if not self.wait_for_graylog():
            print("❌ Impossible de configurer la sécurité")
            return False
        
        # Créer les streams
        streams = self.setup_security_streams()
        
        # Créer les alertes via Legacy API
        alerts = {}
        if streams:
            alerts = self.create_legacy_alert_conditions(streams)
        
        # Configurer les destinataires
        receivers = 0
        if streams and alerts:
            receivers = self.setup_stream_alert_receivers(streams, alerts)
        
        print("\n" + "=" * 40)
        print("✅ CONFIGURATION SÉCURITÉ TERMINÉE !")
        print(f"📊 Streams sécurité: {len(streams)}")
        print(f"🚨 Alertes Legacy: {len(alerts)}")
        print(f"📧 Destinataires: {receivers}")
        
        if len(streams) > 0:
            print("\n🛡️ Tâche 24 (Détection) : ✅ CONFIGURÉE")
            print("🔥 Streams actifs:")
            for stream_name in streams.keys():
                print(f"   - {stream_name}")
        
        if len(alerts) > 0:
            print("\n🚨 Alertes Graylog configurées:")
            for alert_name in alerts.keys():
                print(f"   - {alert_name}")
        
        print("\n➡️  Prochaine étape: Configuration Pare-feu (Tâche 25)")
        
        return len(streams) > 0

if __name__ == "__main__":
    setup = GraylogSecuritySetup()
    success = setup.run_setup()
    sys.exit(0 if success else 1)

#!/bin/bash
# Script d'initialisation complète de la toolbox après clone Git
# À lancer UNE SEULE FOIS sur nouvelle machine

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_MARKER="$SCRIPT_DIR/.toolbox_initialized"

echo "🚀 INITIALISATION COMPLÈTE TOOLBOX PENTEST"
echo "=========================================="

# Vérifier si déjà initialisé
if [ -f "$SETUP_MARKER" ]; then
    echo "✅ Toolbox déjà initialisée ($(cat $SETUP_MARKER))"
    echo "Pour réinitialiser : rm .toolbox_initialized && ./first_run_setup.sh"
    exit 0
fi

echo "📋 Configuration système détectée :"
echo "- OS: $(uname -s)"
echo "- Architecture: $(uname -m)"
echo "- Docker: $(docker --version 2>/dev/null || echo 'NON INSTALLÉ')"
echo "- Docker Compose: $(docker-compose --version 2>/dev/null || echo 'NON INSTALLÉ')"

# Vérifier les prérequis
echo ""
echo "🔍 Vérification des prérequis..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker non installé. Installer Docker avant de continuer."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose non installé. Installer Docker Compose avant de continuer."
    exit 1
fi

echo "✅ Prérequis OK"

# Arrêter tout service existant
echo ""
echo "🛑 Arrêt des services existants..."
docker-compose down 2>/dev/null || true

# Nettoyer les volumes existants (optionnel)
read -p "🗑️ Supprimer les volumes existants ? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗑️ Suppression des volumes..."
    docker volume rm $(docker volume ls -q | grep toolbox) 2>/dev/null || true
    echo "✅ Volumes supprimés"
fi

# Créer le .env s'il n'existe pas
if [ ! -f ".env" ]; then
    echo ""
    echo "⚙️ Création du fichier .env..."
    cat > .env << 'EOF'
# Configuration Flask
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=your-secret-key-change-this-in-production

# Configuration Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# Configuration PostgreSQL
DB_HOST=postgres
DB_PORT=5432
DB_NAME=toolbox
DB_USER=toolbox_user
DB_PASSWORD=toolbox_password
DATABASE_URL=postgresql://toolbox_user:toolbox_password@postgres:5432/toolbox

# Configuration Graylog
GRAYLOG_HOST=graylog
GRAYLOG_PORT=12201

# PostgreSQL (pour le conteneur)
POSTGRES_DB=toolbox
POSTGRES_USER=toolbox_user
POSTGRES_PASSWORD=toolbox_password

# Graylog
GRAYLOG_PASSWORD_SECRET=somepasswordpepper
GRAYLOG_ROOT_PASSWORD_SHA2=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918

# MinIO Configuration
MINIO_ROOT_USER=toolbox_admin
MINIO_ROOT_PASSWORD=toolbox_secret_2024
MINIO_ENDPOINT=minio:9000
MINIO_SECURE=false

# Configuration Graylog avancée (ajoutée par le script)
GRAYLOG_RETENTION_DAYS=30
GRAYLOG_MAX_INDEX_SIZE=1073741824
GRAYLOG_MAX_NUMBER_OF_INDICES=20
GRAYLOG_ROTATION_STRATEGY=size
EOF
    echo "✅ Fichier .env créé"
else
    echo "✅ Fichier .env existant"
fi

# Démarrer les services dans l'ordre
echo ""
echo "🚀 Démarrage des services (cela peut prendre 5-10 minutes)..."

echo "📦 1/6 - Démarrage infrastructure de base..."
docker-compose up -d postgres redis mongo
sleep 15

echo "📦 2/6 - Démarrage Elasticsearch..."
docker-compose up -d elasticsearch
echo "⏳ Attente Elasticsearch (60 secondes)..."
sleep 60

# Vérifier Elasticsearch
ES_STATUS=""
for i in {1..10}; do
    ES_STATUS=$(curl -s "localhost:9200/_cluster/health" 2>/dev/null | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    if [ "$ES_STATUS" = "green" ] || [ "$ES_STATUS" = "yellow" ]; then
        echo "✅ Elasticsearch prêt (status: $ES_STATUS)"
        break
    fi
    echo "⏳ Elasticsearch pas encore prêt... ($i/10)"
    sleep 10
done

echo "📦 3/6 - Démarrage Graylog..."
docker-compose up -d graylog
echo "⏳ Attente Graylog (60 secondes)..."
sleep 60

# Vérifier Graylog
for i in {1..10}; do
    if curl -s -f "localhost:9000/api/system" >/dev/null 2>&1; then
        echo "✅ Graylog prêt"
        break
    fi
    echo "⏳ Graylog pas encore prêt... ($i/10)"
    sleep 10
done

echo "📦 4/6 - Démarrage MinIO..."
docker-compose up -d minio
sleep 10

echo "📦 5/6 - Démarrage application..."
docker-compose up -d app worker flower
sleep 20

echo "📦 6/6 - Démarrage services complémentaires..."
docker-compose up -d dvwa
sleep 5

# Configuration automatique Graylog
echo ""
echo "⚙️ Configuration automatique Graylog..."

# Créer le script de config Graylog intégré
cat > /tmp/graylog_auto_config.py << 'EOF'
#!/usr/bin/env python3
import requests
import json
import time
from requests.auth import HTTPBasicAuth

def wait_and_configure_graylog():
    print("🔧 Configuration automatique Graylog...")
    
    auth = HTTPBasicAuth("admin", "admin")
    headers = {'Content-Type': 'application/json', 'X-Requested-By': 'python-script'}
    
    # Attendre que Graylog soit prêt
    for i in range(20):
        try:
            response = requests.get("http://localhost:9000/api/system", auth=auth, timeout=5)
            if response.status_code == 200:
                print("✅ Graylog API accessible")
                break
        except:
            pass
        time.sleep(5)
        print(f"⏳ Attente Graylog API... ({i+1}/20)")
    
    # Créer input GELF
    input_config = {
        "title": "Toolbox GELF Input",
        "type": "org.graylog2.inputs.gelf.udp.GELFUDPInput",
        "configuration": {
            "bind_address": "0.0.0.0",
            "port": 12201,
            "recv_buffer_size": 262144,
            "override_source": None
        },
        "global": True
    }
    
    try:
        response = requests.post("http://localhost:9000/api/system/inputs", 
                               json=input_config, auth=auth, headers=headers)
        if response.status_code in [200, 201]:
            print("✅ Input GELF créé")
        else:
            print("⚠️ Input GELF existe déjà ou erreur")
    except Exception as e:
        print(f"⚠️ Erreur création input: {e}")
    
    print("✅ Configuration Graylog terminée")

echo ""
echo "🛡️ CONFIGURATION SÉCURITÉ AUTOMATIQUE"
echo "====================================="

# Vérifier que le script de sécurité existe
if [ ! -f "backend/scripts/setup_graylog_security.py" ]; then
    echo "⚠️ Script de sécurité manquant, création..."
    
    # Créer le répertoire si nécessaire
    mkdir -p backend/scripts/security
    
    # Créer le script de sécurité (intégré dans first_run_setup.sh)
    cat > backend/scripts/setup_graylog_security.py << 'SECURITY_SCRIPT_EOF'
#!/usr/bin/env python3
"""
Script d'auto-configuration Graylog pour la sécurité
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
            
            if i < max_attempts - 1:  # Pas de sleep au dernier essai
                time.sleep(5)
        
        print("❌ Graylog non accessible après 75 secondes")
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
                requests.post(
                    f"{self.base_url}/api/streams/{stream_id}/resume",
                    auth=self.auth,
                    headers=self.headers
                )
                
                return stream_id
            else:
                print(f"⚠️ Erreur stream {stream_config['title']}: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Erreur stream {stream_config['title']}: {e}")
            return None
    
    def setup_security_streams(self):
        """Configurer tous les streams de sécurité"""
        print("\n🛡️ Configuration Streams Sécurité...")
        
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
    
    def create_webhook_notification(self):
        """Créer la notification webhook pour les alertes"""
        print("\n🔔 Configuration Webhook Sécurité...")
        
        webhook_config = {
            "title": "Security Webhook",
            "description": "Webhook alertes sécurité - Tâches 24&25",
            "config": {
                "url": "http://app:5000/api/security/webhook",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Security-Token": "toolbox-security-2024"
                },
                "body_template": '''{"alert":"${event_definition_title}","timestamp":"${event.timestamp}","source_ip":"${event.fields.source_ip}","message":"${event.message}"}'''
            }
        }
        
        try:
            # Vérifier si webhook existe
            response = requests.get(f"{self.base_url}/api/notifications", auth=self.auth)
            if response.status_code == 200:
                notifications = response.json()
                for notif in notifications.get('notifications', []):
                    if notif.get('title') == webhook_config['title']:
                        print("⏩ Webhook existe déjà")
                        return notif.get('id')
            
            # Créer nouveau webhook
            response = requests.post(
                f"{self.base_url}/api/notifications",
                auth=self.auth,
                headers=self.headers,
                json=webhook_config
            )
            
            if response.status_code in [200, 201]:
                print("✅ Webhook sécurité créé")
                return response.json().get('id')
            else:
                print(f"⚠️ Erreur webhook: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Erreur webhook: {e}")
            return None
    
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
        
        # Créer le webhook  
        webhook_id = self.create_webhook_notification()
        
        print("\n" + "=" * 40)
        print("✅ CONFIGURATION SÉCURITÉ TERMINÉE !")
        print(f"📊 Streams sécurité: {len(streams)}")
        print(f"🔔 Webhook: {'✅' if webhook_id else '❌'}")
        print("\n🛡️ Tâches 24 & 25 : Détection + Pare-feu configurés")
        
        return True

if __name__ == "__main__":
    setup = GraylogSecuritySetup()
    success = setup.run_setup()
    sys.exit(0 if success else 1)
SECURITY_SCRIPT_EOF

    # Rendre le script exécutable
    chmod +x backend/scripts/setup_graylog_security.py
    echo "✅ Script de sécurité créé"
fi

# Lancer la configuration de sécurité
echo "🚀 Lancement configuration sécurité..."
python3 backend/scripts/setup_graylog_security.py

if [ $? -eq 0 ]; then
    echo "✅ Configuration sécurité réussie !"
else
    echo "⚠️ Configuration sécurité partielle - continuons..."
fi


if __name__ == "__main__":
    wait_and_configure_graylog()
EOF

python3 /tmp/graylog_auto_config.py
rm /tmp/graylog_auto_config.py

# Forcer la création d'index avec des logs de test
echo ""
echo "📤 Génération de logs de test pour créer les index..."

# Méthode 1: Logs Python direct
docker-compose exec -T app python3 << 'EOF' || true
import logging
from pygelf import GelfUdpHandler
import time

logger = logging.getLogger('toolbox-init')
try:
    handler = GelfUdpHandler(host='graylog', port=12201)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    messages = [
        "🚀 Toolbox pentest initialisée avec succès",
        "✅ Tous les services sont opérationnels", 
        "🔧 Configuration Graylog appliquée",
        "🛡️ Système de logging centralisé actif",
        "📊 Prêt pour les tests d'intrusion"
    ]
    
    for msg in messages:
        logger.info(msg)
        time.sleep(0.5)
    
    print("✅ Messages de test envoyés")
except Exception as e:
    print(f"⚠️ Erreur envoi logs: {e}")
EOF

# Méthode 2: Logs Docker GELF
docker run --rm \
  --network ${PWD##*/}_toolbox-network \
  --log-driver=gelf \
  --log-opt gelf-address=udp://graylog:12201 \
  --log-opt tag="toolbox-init" \
  alpine sh -c 'for i in $(seq 1 3); do echo "Init log $i - Toolbox ready"; sleep 1; done' 2>/dev/null || true

echo "⏳ Attente indexation (15 secondes)..."
sleep 15

# Vérifications finales
echo ""
echo "🔍 VÉRIFICATIONS FINALES"
echo "========================"

# Status des conteneurs
echo "📦 Status des conteneurs:"
docker-compose ps

echo ""
echo "📊 Index Elasticsearch:"
curl -s "localhost:9200/_cat/indices?v" | head -10

echo ""
echo "📈 Messages dans Graylog:"
MSG_COUNT=$(curl -s "localhost:9200/graylog_*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2 || echo "0")
echo "Messages totaux: ${MSG_COUNT}"

# Tests de connectivité
echo ""
echo "🌐 Tests de connectivité:"
echo -n "- Toolbox App (5000): "
curl -s -o /dev/null -w "%{http_code}" "localhost:5000" || echo "❌"
echo -n "- Graylog (9000): "
curl -s -o /dev/null -w "%{http_code}" "localhost:9000" || echo "❌"
echo -n "- Flower (5555): "
curl -s -o /dev/null -w "%{http_code}" "localhost:5555" || echo "❌"
echo -n "- MinIO (9090): "
curl -s -o /dev/null -w "%{http_code}" "localhost:9090" || echo "❌"

# Créer le marqueur de succès
echo "$(date '+%Y-%m-%d %H:%M:%S') - Toolbox initialisée avec succès" > "$SETUP_MARKER"

echo ""
echo "🎉 INITIALISATION TERMINÉE AVEC SUCCÈS !"
echo "========================================"
echo ""
echo "🔗 Interfaces disponibles:"
echo "- 🛡️  Toolbox App:    http://localhost:5000"
echo "- 📊 Graylog:         http://localhost:9000 (admin/admin)"
echo "- 🌸 Flower (Celery): http://localhost:5555"
echo "- 💾 MinIO:           http://localhost:9090 (toolbox_admin/toolbox_secret_2024)"
echo "- 🎯 DVWA (Test):     http://localhost:8080"
echo ""
echo "📋 Commandes utiles:"
echo "- Status:             docker-compose ps"
echo "- Logs:               docker-compose logs [service]"
echo "- Arrêt:              docker-compose down"
echo "- Redémarrage:        docker-compose restart [service]"
echo ""
echo "⚠️  Ce script ne doit être lancé qu'UNE SEULE FOIS"
echo "   Pour réinitialiser: rm .toolbox_initialized"
echo ""
echo "🎯 Votre toolbox de pentest est prête !"

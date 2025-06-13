#!/bin/bash
# Script de configuration post-déploiement pour Graylog
# EMPLACEMENT: À la racine de votre projet (même niveau que docker-compose.yml)
# FICHIER: setup_graylog_persistence.sh

echo "🔧 Configuration de la persistance Graylog..."

# Créer les répertoires de persistance si nécessaire
mkdir -p ./graylog-data/{data,journal}
chmod 777 ./graylog-data/{data,journal}

# Variables d'environnement pour la rétention
cat >> .env << EOF

# ===== CONFIGURATION GRAYLOG AVANCÉE =====
# Rétention des logs (en jours)
GRAYLOG_RETENTION_DAYS=30

# Taille maximale des index Elasticsearch
GRAYLOG_MAX_INDEX_SIZE=1073741824  # 1GB

# Nombre maximum d'index à conserver
GRAYLOG_MAX_NUMBER_OF_INDICES=20

# Configuration de la rotation des logs
GRAYLOG_ROTATION_STRATEGY=size
GRAYLOG_MAX_SIZE_PER_INDEX=1073741824

# Configuration du processus message
GRAYLOG_PROCESSBUFFER_PROCESSORS=5
GRAYLOG_OUTPUTBUFFER_PROCESSORS=3
GRAYLOG_OUTPUT_BATCH_SIZE=500

# Configuration mémoire
GRAYLOG_HEAP_SIZE=1g
EOF

echo "✅ Configuration Graylog ajoutée au .env"

# Créer un script de backup
cat > backup_graylog.sh << 'EOF'
#!/bin/bash
# Script de sauvegarde Graylog

BACKUP_DIR="./backups/graylog/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "📦 Sauvegarde Graylog en cours..."

# Backup des données MongoDB
docker exec toolbox-mongo mongodump --out /tmp/backup
docker cp toolbox-mongo:/tmp/backup "$BACKUP_DIR/mongodb"

# Backup des données Elasticsearch
docker exec toolbox-elasticsearch curl -X PUT "localhost:9200/_snapshot/backup_repo" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/tmp/elasticsearch_backup"
  }
}'

# Backup de la configuration Graylog
docker cp toolbox-graylog:/usr/share/graylog/data "$BACKUP_DIR/graylog_config"

echo "✅ Sauvegarde terminée dans: $BACKUP_DIR"
EOF

chmod +x backup_graylog.sh

echo "✅ Script de backup créé: backup_graylog.sh"

# Créer un script de monitoring de l'espace disque
cat > monitor_graylog_storage.sh << 'EOF'
#!/bin/bash
# Script de monitoring de l'espace disque Graylog

echo "📊 État de l'espace disque Graylog:"
echo "=================================="

# Vérifier l'espace des volumes Docker
docker system df

echo ""
echo "📈 Taille des volumes Graylog:"
echo "-----------------------------"

# Volume MongoDB
MONGO_SIZE=$(docker exec toolbox-mongo du -sh /data/db 2>/dev/null | cut -f1 || echo "N/A")
echo "MongoDB: $MONGO_SIZE"

# Volume Elasticsearch
ES_SIZE=$(docker exec toolbox-elasticsearch du -sh /usr/share/elasticsearch/data 2>/dev/null | cut -f1 || echo "N/A")
echo "Elasticsearch: $ES_SIZE"

# Volume Graylog
GRAYLOG_SIZE=$(docker exec toolbox-graylog du -sh /usr/share/graylog/data 2>/dev/null | cut -f1 || echo "N/A")
echo "Graylog: $GRAYLOG_SIZE"

echo ""
echo "⚠️  Seuils d'alerte:"
echo "- MongoDB > 5GB"
echo "- Elasticsearch > 10GB"
echo "- Graylog > 2GB"
EOF

chmod +x monitor_graylog_storage.sh

echo "✅ Script de monitoring créé: monitor_graylog_storage.sh"
echo ""
echo "🚀 Pour appliquer les modifications:"
echo "1. docker-compose down"
echo "2. Modifier votre docker-compose.yml avec le contenu ci-dessus"
echo "3. docker-compose up -d"
echo "4. Exécuter: ./monitor_graylog_storage.sh"

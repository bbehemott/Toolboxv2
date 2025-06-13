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

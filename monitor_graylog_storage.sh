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

#!/bin/bash
# Script de diagnostic complet pour Graylog + Elasticsearch

echo "🔍 DIAGNOSTIC GRAYLOG/ELASTICSEARCH"
echo "=================================="

# 1. État des conteneurs
echo "📦 État des conteneurs:"
docker-compose ps | grep -E "(graylog|elasticsearch|mongo)"

echo ""
echo "🔗 Connectivité réseau:"
docker exec toolbox-graylog ping -c 2 elasticsearch 2>/dev/null || echo "❌ Graylog ne peut pas ping Elasticsearch"
docker exec toolbox-elasticsearch curl -s localhost:9200 >/dev/null && echo "✅ Elasticsearch répond" || echo "❌ Elasticsearch ne répond pas"

# 2. Vérifier Elasticsearch
echo ""
echo "🔍 État Elasticsearch:"
ES_HEALTH=$(curl -s "localhost:9200/_cluster/health" 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "✅ Elasticsearch accessible"
    echo "Cluster Health: $(echo $ES_HEALTH | grep -o '"status":"[^"]*' | cut -d'"' -f4)"
else
    echo "❌ Elasticsearch inaccessible"
fi

# 3. Lister les index
echo ""
echo "📋 Index Elasticsearch:"
curl -s "localhost:9200/_cat/indices?v" 2>/dev/null || echo "❌ Impossible de lister les index"

# 4. Vérifier la configuration Graylog
echo ""
echo "⚙️ Configuration Graylog:"
docker exec toolbox-graylog cat /usr/share/graylog/data/config/graylog.conf 2>/dev/null | grep -E "(elasticsearch|mongodb)" || echo "❌ Config Graylog inaccessible"

# 5. Logs récents
echo ""
echo "📄 Logs récents Graylog (erreurs):"
docker-compose logs graylog 2>/dev/null | tail -20 | grep -i "error\|exception\|failed" || echo "Pas d'erreurs récentes trouvées"

echo ""
echo "📄 Logs récents Elasticsearch (erreurs):"
docker-compose logs elasticsearch 2>/dev/null | tail -20 | grep -i "error\|exception\|failed" || echo "Pas d'erreurs récentes trouvées"

# 6. Test de création d'index manuel
echo ""
echo "🧪 Test création d'index manuel:"
INDEX_RESPONSE=$(curl -s -X PUT "localhost:9200/test-index" -H 'Content-Type: application/json' -d'
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  }
}' 2>/dev/null)

if echo "$INDEX_RESPONSE" | grep -q "acknowledged"; then
    echo "✅ Création d'index test réussie"
    curl -s -X DELETE "localhost:9200/test-index" >/dev/null 2>&1
else
    echo "❌ Échec création d'index test"
    echo "Réponse: $INDEX_RESPONSE"
fi

# 7. Vérifier les volumes et permissions
echo ""
echo "💾 Volumes et permissions:"
docker exec toolbox-elasticsearch ls -la /usr/share/elasticsearch/data 2>/dev/null | head -5 || echo "❌ Volume Elasticsearch inaccessible"
docker exec toolbox-mongo ls -la /data/db 2>/dev/null | head -3 || echo "❌ Volume MongoDB inaccessible"

# 8. Mémoire et ressources
echo ""
echo "💻 Ressources système:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep -E "(elasticsearch|graylog|mongo)"

echo ""
echo "🎯 RECOMMANDATIONS:"
echo "=================="

# Analyser les résultats et donner des recommandations
if ! curl -s "localhost:9200/_cluster/health" >/dev/null 2>&1; then
    echo "❌ PROBLÈME: Elasticsearch n'est pas accessible"
    echo "   Solutions:"
    echo "   1. docker-compose restart elasticsearch"
    echo "   2. Vérifier les logs: docker-compose logs elasticsearch"
    echo "   3. Augmenter la mémoire si nécessaire"
fi

if ! docker exec toolbox-graylog ping -c 1 elasticsearch >/dev/null 2>&1; then
    echo "❌ PROBLÈME: Graylog ne peut pas contacter Elasticsearch"
    echo "   Solutions:"
    echo "   1. Vérifier le réseau Docker: docker network ls"
    echo "   2. Redémarrer les services: docker-compose restart"
fi

INDEX_COUNT=$(curl -s "localhost:9200/_cat/indices" 2>/dev/null | wc -l)
if [ "$INDEX_COUNT" -eq 0 ]; then
    echo "⚠️ PROBLÈME: Aucun index Graylog trouvé"
    echo "   Solutions:"
    echo "   1. Forcer la création: python test_gelf_logs.py"
    echo "   2. Redémarrer Graylog: docker-compose restart graylog"
    echo "   3. Vérifier les inputs dans l'interface Graylog"
fi

echo ""
echo "🔧 COMMANDES DE RÉPARATION RAPIDE:"
echo "================================="
echo "# Redémarrage complet de la stack logs:"
echo "docker-compose restart elasticsearch mongo graylog"
echo ""
echo "# Nettoyage et redémarrage:"
echo "docker-compose down"
echo "docker system prune -f"
echo "docker-compose up -d"
echo ""
echo "# Forcer création d'index:"
echo "python test_gelf_logs.py"

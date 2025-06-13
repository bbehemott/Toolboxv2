#!/bin/bash
# Création des scripts de maintenance permanents

echo "📝 Création des scripts de maintenance..."

# 1. Script de status
cat > status.sh << 'EOF'
#!/bin/bash
# Status complet de la toolbox

echo "📊 STATUS TOOLBOX PENTEST"
echo "========================"

echo "📦 Conteneurs:"
docker-compose ps

echo ""
echo "💾 Volumes:"
docker volume ls | grep toolbox

echo ""
echo "📊 Elasticsearch:"
curl -s "localhost:9200/_cat/indices?v" | grep graylog || echo "Aucun index Graylog"

echo ""
echo "📈 Messages Graylog:"
MSG_COUNT=$(curl -s "localhost:9200/graylog_*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2 || echo "0")
echo "Messages totaux: ${MSG_COUNT}"

echo ""
echo "🌐 Connectivité:"
services=("5000:Toolbox" "9000:Graylog" "5555:Flower" "9090:MinIO" "8080:DVWA")
for service in "${services[@]}"; do
    port=$(echo $service | cut -d: -f1)
    name=$(echo $service | cut -d: -f2)
    status=$(curl -s -o /dev/null -w "%{http_code}" "localhost:$port" 2>/dev/null || echo "000")
    if [ "$status" = "200" ] || [ "$status" = "302" ]; then
        echo "✅ $name ($port): OK"
    else
        echo "❌ $name ($port): $status"
    fi
done
EOF

# 2. Script de maintenance Graylog
cat > maintain_graylog.sh << 'EOF'
#!/bin/bash
# Maintenance Graylog

echo "🔧 MAINTENANCE GRAYLOG"
echo "====================="

case "${1:-status}" in
    "status"|"")
        echo "📊 Status Graylog:"
        docker-compose ps graylog elasticsearch mongo
        ;;
    "restart")
        echo "🔄 Redémarrage Graylog..."
        docker-compose restart mongo elasticsearch graylog
        ;;
    "logs")
        echo "📄 Logs récents:"
        docker-compose logs --tail=50 graylog
        ;;
    "clean")
        echo "🗑️ Nettoyage index anciens..."
        curl -X DELETE "localhost:9200/graylog_*" -H "X-Requested-By: maintenance"
        docker-compose restart graylog
        ;;
    "rebuild")
        echo "🔨 Reconstruction des index ranges..."
        curl -X POST -u admin:admin "localhost:9000/api/system/indices/ranges/rebuild" -H "X-Requested-By: maintenance"
        ;;
    *)
        echo "Usage: $0 [status|restart|logs|clean|rebuild]"
        ;;
esac
EOF

# 3. Script de monitoring
cat > monitor.sh << 'EOF'
#!/bin/bash
# Monitoring en temps réel

echo "📊 MONITORING TOOLBOX"
echo "===================="

while true; do
    clear
    echo "📊 MONITORING TOOLBOX - $(date)"
    echo "================================"
    
    echo "📦 Conteneurs:"
    docker-compose ps | head -10
    
    echo ""
    echo "💻 Ressources:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | head -8
    
    echo ""
    echo "📈 Messages Graylog:"
    MSG_COUNT=$(curl -s "localhost:9200/graylog_*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2 || echo "0")
    echo "Total: ${MSG_COUNT} messages"
    
    echo ""
    echo "🔄 Actualisation dans 30s... (Ctrl+C pour arrêter)"
    sleep 30
done
EOF

# 4. Script de backup rapide
cat > quick_backup.sh << 'EOF'
#!/bin/bash
# Backup rapide des configurations

BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "💾 BACKUP RAPIDE TOOLBOX"
echo "========================"

echo "📄 Sauvegarde des configurations..."
cp -r backend/ "$BACKUP_DIR/"
cp docker-compose.yml "$BACKUP_DIR/"
cp .env "$BACKUP_DIR/" 2>/dev/null || echo "Pas de .env"
cp *.sh "$BACKUP_DIR/" 2>/dev/null || true

echo "📊 Export PostgreSQL..."
docker exec toolbox-postgres pg_dump -U toolbox_user toolbox > "$BACKUP_DIR/postgres_dump.sql" 2>/dev/null || echo "Erreur dump PostgreSQL"

echo "📋 Informations système..."
docker-compose ps > "$BACKUP_DIR/containers_status.txt"
docker volume ls > "$BACKUP_DIR/volumes_list.txt"

echo "✅ Backup créé: $BACKUP_DIR"
echo "📦 Taille: $(du -sh $BACKUP_DIR | cut -f1)"
EOF

# 5. Script de fix rapide
cat > fix_common_issues.sh << 'EOF'
#!/bin/bash
# Correction des problèmes courants

echo "🔧 CORRECTION PROBLÈMES COURANTS"
echo "================================"

case "${1:-menu}" in
    "graylog")
        echo "🔧 Fix Graylog index_not_found..."
        docker-compose exec -T app python3 << 'PYTHON'
import logging
from pygelf import GelfUdpHandler
logger = logging.getLogger('fix-graylog')
handler = GelfUdpHandler(host='graylog', port=12201)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
for i in range(5):
    logger.info(f"Fix message {i+1} - Creating indexes")
print("✅ Messages envoyés")
PYTHON
        ;;
    "services")
        echo "🔄 Redémarrage services..."
        docker-compose restart
        ;;
    "permissions")
        echo "🔒 Fix permissions..."
        sudo chown -R $USER:$USER .
        chmod +x *.sh
        ;;
    "network")
        echo "🌐 Recréation réseau..."
        docker-compose down
        docker network prune -f
        docker-compose up -d
        ;;
    "menu"|*)
        echo "Problèmes courants:"
        echo "1. ./fix_common_issues.sh graylog     - Fix index Graylog"
        echo "2. ./fix_common_issues.sh services    - Redémarrage services"
        echo "3. ./fix_common_issues.sh permissions - Fix permissions"
        echo "4. ./fix_common_issues.sh network     - Recréation réseau"
        ;;
esac
EOF

# Rendre tous les scripts exécutables
chmod +x *.sh

echo "✅ Scripts de maintenance créés:"
echo "- status.sh              - Status complet"
echo "- maintain_graylog.sh    - Maintenance Graylog"  
echo "- monitor.sh             - Monitoring temps réel"
echo "- quick_backup.sh        - Backup rapide"
echo "- fix_common_issues.sh   - Corrections communes"

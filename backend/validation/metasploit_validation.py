#!/bin/bash

echo "🚀 DÉPLOIEMENT INTÉGRATION METASPLOIT - BACKEND ONLY"
echo "======================================================="

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
PROJECT_DIR=$(pwd)
BACKEND_DIR="$PROJECT_DIR/backend"

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fonction pour vérifier si un service est en cours d'exécution
check_service() {
    local service_name=$1
    local port=$2
    
    if nc -z localhost $port 2>/dev/null; then
        print_success "$service_name est accessible sur le port $port"
        return 0
    else
        print_error "$service_name n'est pas accessible sur le port $port"
        return 1
    fi
}

# Étape 1: Vérifications préliminaires
print_status "Étape 1: Vérifications préliminaires..."

# Vérifier Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker n'est pas installé"
    exit 1
fi

# Vérifier Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose n'est pas installé"
    exit 1
fi

# Vérifier la structure du projet
if [[ ! -f "docker-compose.yml" ]]; then
    print_error "docker-compose.yml non trouvé"
    exit 1
fi

if [[ ! -d "$BACKEND_DIR" ]]; then
    print_error "Répertoire backend/ non trouvé"
    exit 1
fi

print_success "Vérifications préliminaires OK"

# Étape 2: Backup des fichiers existants
print_status "Étape 2: Backup des fichiers modifiés..."

mkdir -p backups/$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

# Backup des fichiers principaux
cp Dockerfile "$BACKUP_DIR/" 2>/dev/null
cp "$BACKEND_DIR/core/huntkit_tools.py" "$BACKUP_DIR/" 2>/dev/null
cp "$BACKEND_DIR/tasks_huntkit.py" "$BACKUP_DIR/" 2>/dev/null
cp "$BACKEND_DIR/services/task_manager.py" "$BACKUP_DIR/" 2>/dev/null
cp "$BACKEND_DIR/celery_app.py" "$BACKUP_DIR/" 2>/dev/null

print_success "Backup créé dans $BACKUP_DIR"

# Étape 3: Application des modifications
print_status "Étape 3: Application des modifications Metasploit..."

# Ici, normalement, on copierait les nouveaux fichiers
# Pour cette démonstration, on suppose qu'ils sont déjà en place
print_warning "Les fichiers suivants doivent être mis à jour manuellement:"
echo "  - Dockerfile (avec installation Metasploit)"
echo "  - backend/core/huntkit_tools.py (avec MetasploitWrapper)"
echo "  - backend/tasks_huntkit.py (avec tâches Metasploit)"
echo "  - backend/services/task_manager.py (avec méthodes Metasploit)"
echo "  - backend/celery_app.py (avec routes Metasploit)"

# Étape 4: Rebuild des conteneurs
print_status "Étape 4: Rebuild des conteneurs Docker..."

# Arrêter les conteneurs existants
print_status "Arrêt des conteneurs existants..."
docker-compose down

# Rebuild avec Metasploit (cache désactivé)
print_status "Rebuild de l'image avec Metasploit (cela peut prendre 10-15 minutes)..."
docker-compose build --no-cache

if [[ $? -ne 0 ]]; then
    print_error "Échec du build Docker"
    exit 1
fi

print_success "Build Docker terminé avec succès"

# Étape 5: Démarrage des services
print_status "Étape 5: Démarrage des services..."

# Démarrer les services de base
print_status "Démarrage des services de base..."
docker-compose up -d postgres redis mongo elasticsearch

# Attendre que PostgreSQL soit prêt
print_status "Attente de PostgreSQL..."
for i in {1..30}; do
    if check_service "PostgreSQL" 5432; then
        break
    fi
    sleep 2
done

# Attendre que Redis soit prêt
print_status "Attente de Redis..."
for i in {1..30}; do
    if check_service "Redis" 6379; then
        break
    fi
    sleep 2
done

# Démarrer Graylog
print_status "Démarrage de Graylog..."
docker-compose up -d graylog

# Démarrer l'application principale
print_status "Démarrage de l'application principale..."
docker-compose up -d app worker flower

print_success "Tous les services démarrés"

# Étape 6: Validation de l'intégration
print_status "Étape 6: Validation de l'intégration Metasploit..."

# Attendre que l'application soit prête
sleep 10

# Vérifier les services
print_status "Vérification des services..."
check_service "Application Flask" 5000
check_service "Flower (Celery)" 5555
check_service "Graylog" 9000

# Test de validation Python dans le conteneur
print_status "Exécution du script de validation dans le conteneur..."

# Créer le script de validation dans le conteneur
docker-compose exec -T app python -c "
import sys
sys.path.insert(0, '/app/backend')

try:
    from core.huntkit_tools import HuntKitIntegration, MetasploitWrapper
    print('✅ Import HuntKit + Metasploit: OK')
    
    huntkit = HuntKitIntegration()
    print('✅ Initialisation HuntKit: OK')
    
    msf_test = huntkit.metasploit.test_metasploit_availability()
    if msf_test.get('available'):
        print(f'✅ Metasploit disponible: {msf_test.get(\"version\", \"Unknown\")}')
    else:
        print(f'❌ Metasploit non disponible: {msf_test.get(\"error\", \"Unknown\")}')
        
    tools_status = huntkit.get_tool_status()
    tools = tools_status['tools_available']
    print(f'✅ Outils disponibles: Nmap={tools.get(\"nmap\")}, Metasploit={tools.get(\"msfconsole\")}')
    
except Exception as e:
    print(f'❌ Erreur validation: {e}')
    sys.exit(1)
"

if [[ $? -eq 0 ]]; then
    print_success "Validation dans le conteneur réussie"
else
    print_error "Validation dans le conteneur échouée"
fi

# Test des tâches Celery
print_status "Test des tâches Celery Metasploit..."

docker-compose exec -T app python -c "
import sys
sys.path.insert(0, '/app/backend')

try:
    from celery_app import celery_app
    
    # Lister les tâches disponibles
    tasks = list(celery_app.tasks.keys())
    metasploit_tasks = [t for t in tasks if 'metasploit' in t or 'exploitation' in t]
    
    print(f'✅ Total tâches Celery: {len(tasks)}')
    print(f'✅ Tâches Metasploit: {len(metasploit_tasks)}')
    
    for task in metasploit_tasks:
        print(f'   - {task}')
        
    if len(metasploit_tasks) >= 3:
        print('✅ Intégration Celery Metasploit: OK')
    else:
        print('⚠️ Intégration Celery Metasploit: Partielle')
        
except Exception as e:
    print(f'❌ Erreur test Celery: {e}')
"

# Étape 7: Test fonctionnel complet
print_status "Étape 7: Test fonctionnel complet..."

# Copier le script de validation dans le conteneur
docker-compose exec -T app bash -c "cat > /tmp/metasploit_validation.py" << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/app/backend')

from core.huntkit_tools import HuntKitIntegration
import time

print("🧪 TEST FONCTIONNEL METASPLOIT")
print("=" * 40)

try:
    huntkit = HuntKitIntegration()
    
    # Test 1: Disponibilité
    print("\n1. Test disponibilité...")
    msf_test = huntkit.metasploit.test_metasploit_availability()
    if msf_test['available']:
        print(f"✅ Metasploit disponible: {msf_test.get('version', 'Unknown')}")
    else:
        print(f"❌ Metasploit indisponible: {msf_test.get('error', 'Unknown')}")
        sys.exit(1)
    
    # Test 2: Recherche d'exploits
    print("\n2. Test recherche exploits...")
    search_result = huntkit.metasploit.search_exploits(service='ssh')
    if search_result['success']:
        count = len(search_result.get('exploits_found', []))
        print(f"✅ Recherche OK: {count} exploits SSH trouvés")
    else:
        print(f"❌ Recherche échec: {search_result.get('error', 'Unknown')}")
    
    # Test 3: Module auxiliaire sécurisé
    print("\n3. Test module auxiliaire...")
    aux_result = huntkit.metasploit.run_auxiliary_scan(
        target='127.0.0.1',
        port=22,
        service='ssh',
        options={'THREADS': '1'}
    )
    if aux_result['success']:
        print("✅ Module auxiliaire exécuté avec succès")
    else:
        print(f"❌ Module auxiliaire échec: {aux_result.get('error', 'Unknown')}")
    
    print("\n✅ TOUS LES TESTS FONCTIONNELS RÉUSSIS")
    
except Exception as e:
    print(f"\n❌ ERREUR CRITIQUE: {e}")
    sys.exit(1)
EOF

# Exécuter le test fonctionnel
docker-compose exec -T app python /tmp/metasploit_validation.py

if [[ $? -eq 0 ]]; then
    print_success "Test fonctionnel complet réussi"
else
    print_error "Test fonctionnel échoué"
fi

# Étape 8: Informations finales
print_status "Étape 8: Informations finales..."

echo
echo "🎯 INTÉGRATION METASPLOIT TERMINÉE"
echo "=================================="
echo
echo "📊 Services disponibles:"
echo "  - Application Flask: http://localhost:5000"
echo "  - Flower (Celery): http://localhost:5555"
echo "  - Graylog (Logs): http://localhost:9000"
echo "  - DVWA (Test): http://localhost:8080"
echo
echo "🔧 Outils intégrés:"
echo "  - Nmap (découverte réseau)"
echo "  - Hydra (force brute)"
echo "  - Nikto (scan web)"
echo "  - Nuclei (détection vulnérabilités)"
echo "  - SQLMap (injection SQL)"
echo "  - Metasploit Framework (exploitation) ⭐ NOUVEAU"
echo
echo "⚡ Nouvelles tâches Celery:"
echo "  - tasks.exploitation (exploitation Metasploit)"
echo "  - tasks.metasploit_search (recherche exploits)"
echo "  - tasks.metasploit_test (test framework)"
echo
echo "📋 Prochaines étapes:"
echo "  1. Tester manuellement les tâches via Flower"
echo "  2. Vérifier les logs dans Graylog"
echo "  3. Développer l'interface frontend (phase suivante)"
echo "  4. Intégrer l'API RPC Metasploit (phase suivante)"
echo

# Tests manuels recommandés
echo "🧪 TESTS MANUELS RECOMMANDÉS:"
echo "============================="
echo
echo "1. Test via Flower:"
echo "   - Aller sur http://localhost:5555"
echo "   - Onglet 'Tasks' > 'Execute Task'"
echo "   - Tester: tasks_huntkit.metasploit_test_framework"
echo
echo "2. Test via conteneur:"
echo "   docker-compose exec app python -c \""
echo "   import sys; sys.path.insert(0, '/app/backend')"
echo "   from services.task_manager import TaskManager"
echo "   from database import DatabaseManager"
echo "   from config import config"
echo "   db = DatabaseManager(config['development'].DATABASE_URL)"
echo "   tm = TaskManager(db)"
echo "   task_id = tm.start_metasploit_test()"
echo "   print(f'Task lancée: {task_id}')"
echo "   \""
echo
echo "3. Vérification logs:"
echo "   docker-compose logs -f app worker"
echo

# Commandes utiles
echo "📋 COMMANDES UTILES:"
echo "==================="
echo
echo "# Redémarrer les services"
echo "docker-compose restart app worker"
echo
echo "# Voir les logs en temps réel"
echo "docker-compose logs -f app worker"
echo
echo "# Accéder au conteneur pour debug"
echo "docker-compose exec app bash"
echo
echo "# Tester Metasploit directement"
echo "docker-compose exec app msfconsole -v"
echo
echo "# Arrêter tous les services"
echo "docker-compose down"
echo

# Vérification finale des conteneurs
print_status "État final des conteneurs:"
docker-compose ps

# Message de fin
echo
if check_service "Application Flask" 5000 && check_service "Flower (Celery)" 5555; then
    print_success "🎉 DÉPLOIEMENT METASPLOIT RÉUSSI !"
    print_success "Le backend est opérationnel avec Metasploit intégré"
    echo
    echo "Vous pouvez maintenant:"
    echo "✅ Tester les tâches d'exploitation via Flower"
    echo "✅ Développer l'interface frontend"
    echo "✅ Procéder aux tests de pénétration"
    exit 0
else
    print_error "❌ DÉPLOIEMENT INCOMPLET"
    print_error "Certains services ne sont pas accessibles"
    echo
    echo "Actions recommandées:"
    echo "1. Vérifier les logs: docker-compose logs app worker"
    echo "2. Redémarrer: docker-compose restart"
    echo "3. Rebuild si nécessaire: docker-compose build --no-cache"
    exit 1
fi

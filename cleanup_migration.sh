#!/bin/bash
echo "🧹 Nettoyage post-migration PostgreSQL..."

# Fichiers de backup
echo "📁 Suppression des fichiers de backup..."
rm -f backend/database.py.bak
rm -f backend/database.py.sqlite_backup
rm -f backend/config.py.bak
rm -f backend/*.bak

# Script de migration temporaire
echo "📁 Suppression script de migration..."
rm -f backend/migrate_to_postgresql.py

# Fichiers SQLite résiduels
echo "📁 Suppression fichiers SQLite..."
find . -name "*.db" -delete 2>/dev/null || true
find . -name "*.sqlite*" -delete 2>/dev/null || true

# Cache Python
echo "📁 Nettoyage cache Python..."
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true

# Fichiers temporaires
echo "📁 Suppression fichiers temporaires..."
rm -f .DS_Store backend/.DS_Store 2>/dev/null || true
rm -f *~ backend/*~ 2>/dev/null || true
rm -f *.log 2>/dev/null || true

echo "✅ Nettoyage terminé !"
echo ""
echo "📊 Vérification - Fichiers SQLite restants :"
if find . -name "*.db" -o -name "*.sqlite*" | grep -q .; then
    echo "⚠️  Fichiers SQLite trouvés :"
    find . -name "*.db" -o -name "*.sqlite*"
else
    echo "✅ Aucun fichier SQLite trouvé - Migration propre !"
fi

echo ""
echo "📁 Structure finale backend/ :"
ls -la backend/ | grep -E "\.(py|txt)$" | head -10

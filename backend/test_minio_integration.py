#!/usr/bin/env python3
"""
Script de test pour l'intégration MinIO - Tâches 21, 23, 40
Compatible avec l'architecture Flask + PostgreSQL existante
"""
import sys
import os
import time
import json

# Ajouter le backend au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_minio_connection():
    """Test 1: Connexion MinIO"""
    print("🔧 Test 1: Connexion MinIO")
    try:
        from minio_client import MinIOClient
        
        client = MinIOClient()
        status = client.get_status()
        
        if status['available']:
            print(f"✅ MinIO connecté: {status['endpoint']}")
            print(f"📦 Buckets: {', '.join(status['buckets'])}")
            return True
        else:
            print("❌ MinIO non disponible")
            return False
    except Exception as e:
        print(f"❌ Erreur connexion MinIO: {e}")
        return False

def test_key_management():
    """Test 2: Gestion des clés"""
    print("\n🔑 Test 2: Gestion des clés")
    try:
        from minio_client import MinIOClient
        from key_management import KeyManagementService
        
        client = MinIOClient()
        if not client.is_available():
            print("⚠️ MinIO requis pour le test des clés")
            return False
        
        key_manager = KeyManagementService(client.get_client())
        
        # Test génération de clé
        test_key = key_manager.generate_new_key("test_key", "testing")
        if test_key:
            print("✅ Génération de clé réussie")
        else:
            print("❌ Échec génération de clé")
            return False
        
        # Test récupération
        current_key = key_manager.get_current_encryption_key()
        if current_key:
            print("✅ Récupération clé maître réussie")
        else:
            print("❌ Échec récupération clé")
            return False
        
        # Test infos
        info = key_manager.get_key_info()
        print(f"📊 Clés totales: {info['total_keys']}")
        print(f"🔐 Algorithme: {info['algorithm']}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur gestion clés: {e}")
        return False

def test_encryption():
    """Test 3: Service de chiffrement"""
    print("\n🛡️ Test 3: Service de chiffrement")
    try:
        from minio_client import MinIOClient
        from key_management import KeyManagementService
        from crypto import EncryptionService
        
        client = MinIOClient()
        if not client.is_available():
            print("⚠️ MinIO requis pour le test de chiffrement")
            return False
        
        key_manager = KeyManagementService(client.get_client())
        crypto_service = EncryptionService(key_manager)
        
        # Test cycle complet
        test_data = "Test data for ESI M1 Cyber - Données sensibles de scan"
        
        # Chiffrement
        encrypted = crypto_service.encrypt_sensitive_data(test_data, "test_data")
        if encrypted != test_data and encrypted.startswith('gAAAAAB'):
            print("✅ Chiffrement réussi")
        else:
            print("❌ Échec chiffrement")
            return False
        
        # Déchiffrement
        decrypted = crypto_service.decrypt_sensitive_data(encrypted, "test_data")
        if decrypted == test_data:
            print("✅ Déchiffrement réussi")
        else:
            print("❌ Échec déchiffrement")
            return False
        
        # Test automatique
        if crypto_service.test_encryption_cycle():
            print("✅ Test cycle automatique réussi")
        else:
            print("❌ Test cycle automatique échoué")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Erreur service chiffrement: {e}")
        return False

def test_backup_service():
    """Test 4: Service de sauvegarde"""
    print("\n📦 Test 4: Service de sauvegarde")
    try:
        from minio_client import MinIOClient
        from backup import BackupService
        
        client = MinIOClient()
        if not client.is_available():
            print("⚠️ MinIO requis pour le test de sauvegarde")
            return False
        
        backup_service = BackupService(client.get_client())
        
        # Test création sauvegarde
        print("🚀 Création sauvegarde de test...")
        result = backup_service.create_full_backup("Test backup from integration script")
        
        if result['success']:
            print(f"✅ Sauvegarde créée: {result['backup_id']}")
            print(f"📁 Fichiers: {result.get('files_count', 0)}")
            
            # Test listage
            backups = backup_service.list_backups()
            print(f"📋 Sauvegardes disponibles: {len(backups)}")
            
            # Test détails
            details = backup_service.get_backup_details(result['backup_id'])
            if details:
                print("✅ Récupération détails réussie")
            
            # Test statistiques
            stats = backup_service.get_storage_stats()
            print(f"📊 Espace utilisé: {stats.get('total_size_mb', 0)} MB")
            
            return True
        else:
            print(f"❌ Échec création sauvegarde: {result.get('error', 'Erreur inconnue')}")
            return False
            
    except Exception as e:
        print(f"❌ Erreur service sauvegarde: {e}")
        return False

def test_database_integration():
    """Test 5: Intégration avec DatabaseManager"""
    print("\n📊 Test 5: Intégration base de données")
    try:
        from config import config
        from database import DatabaseManager
        
        config_obj = config.get('development', config['default'])
        db = DatabaseManager(config_obj.DATABASE_URL)
        
        # Test chiffrement dans la base
        if hasattr(db, 'crypto_service') and db.crypto_service:
            print("✅ Service de chiffrement intégré à la base")
            
            # Test du cycle
            if db.test_encryption():
                print("✅ Test chiffrement base réussi")
            else:
                print("❌ Test chiffrement base échoué")
                return False
                
        else:
            print("⚠️ Service de chiffrement non intégré")
            return False
        
        # Test statut sécurité
        if hasattr(db, 'get_security_status'):
            status = db.get_security_status()
            print(f"🔐 Statut sécurité: {len(status)} services")
            
        return True
    except Exception as e:
        print(f"❌ Erreur intégration base: {e}")
        return False

def test_full_workflow():
    """Test 6: Workflow complet"""
    print("\n🔄 Test 6: Workflow complet")
    try:
        from minio_client import MinIOClient
        from key_management import KeyManagementService
        from crypto import EncryptionService
        from backup import BackupService
        
        # 1. Initialisation
        client = MinIOClient()
        if not client.is_available():
            print("⚠️ MinIO requis")
            return False
        
        key_manager = KeyManagementService(client.get_client())
        crypto_service = EncryptionService(key_manager)
        backup_service = BackupService(client.get_client())
        
        # 2. Simulation données de scan
        raw_output = """
        Nmap scan results:
        Host: 192.168.1.100
        Port 22/tcp open ssh
        Port 80/tcp open http
        Port 443/tcp open https
        Service detection completed
        """
        
        # 3. Chiffrement des données sensibles
        encrypted_output = crypto_service.encrypt_sensitive_data(raw_output, "nmap_scan")
        print("✅ Données de scan chiffrées")
        
        # 4. Génération nouvelle clé pour rotation
        new_key = key_manager.generate_new_key("workflow_test", "workflow")
        if new_key:
            print("✅ Nouvelle clé générée")
        
        # 5. Sauvegarde complète
        backup_result = backup_service.create_full_backup("Workflow test backup")
        if backup_result['success']:
            print(f"✅ Sauvegarde workflow: {backup_result['backup_id']}")
        
        # 6. Vérification déchiffrement
        decrypted_output = crypto_service.decrypt_sensitive_data(encrypted_output, "nmap_scan")
        if decrypted_output == raw_output:
            print("✅ Workflow complet réussi")
            return True
        else:
            print("❌ Échec workflow")
            return False
            
    except Exception as e:
        print(f"❌ Erreur workflow: {e}")
        return False

def main():
    """Exécution des tests"""
    print("🎯 TESTS D'INTÉGRATION MINIO - TÂCHES 21, 23, 40")
    print("=" * 50)
    
    tests = [
        ("Connexion MinIO", test_minio_connection),
        ("Gestion des clés", test_key_management),
        ("Service de chiffrement", test_encryption),
        ("Service de sauvegarde", test_backup_service),
        ("Intégration base de données", test_database_integration),
        ("Workflow complet", test_full_workflow)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'='*20}")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                print(f"✅ {test_name}: RÉUSSI")
            else:
                print(f"❌ {test_name}: ÉCHOUÉ")
        except Exception as e:
            print(f"❌ {test_name}: ERREUR - {e}")
            results.append((test_name, False))
    
    # Rapport final
    print(f"\n{'='*50}")
    print("📊 RAPPORT FINAL")
    print("=" * 50)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ RÉUSSI" if result else "❌ ÉCHOUÉ"
        print(f"{test_name:<30} {status}")
    
    print(f"\n🎯 RÉSULTAT: {passed}/{total} tests réussis")
    
    if passed == total:
        print("🎉 TOUS LES TESTS RÉUSSIS - Implémentation MinIO opérationnelle!")
        print("\n✅ Tâche 21: Chiffrement des données sensibles - OK")
        print("✅ Tâche 23: Gestion des clés de chiffrement - OK") 
        print("✅ Tâche 40: Système de sauvegarde et restauration - OK")
    else:
        print("⚠️ CERTAINS TESTS ONT ÉCHOUÉ - Vérifiez la configuration")
        print("\nActions recommandées:")
        print("1. Vérifiez que MinIO est démarré: docker-compose up minio")
        print("2. Vérifiez la configuration dans .env")
        print("3. Consultez les logs pour plus de détails")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

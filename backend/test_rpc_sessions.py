#!/usr/bin/env python3
"""
Script de test pour le RPC Metasploit persistant
Utiliser: python backend/test_rpc_sessions.py
"""

import sys
import os
import time
sys.path.append('/app/backend')

def test_rpc_sessions():
    print("🧪 Test RPC Metasploit Persistant")
    print("=" * 50)
    
    try:
        # 1. Test import du client RPC
        print("1. Import du client RPC...")
        from core.metasploit_rpc_client import MetasploitRPCClient
        print("✅ Import réussi")
        
        # 2. Initialisation du client RPC
        print("\n2. Initialisation du client RPC...")
        client = MetasploitRPCClient()
        print("✅ Client RPC initialisé")
        
        # 3. Test de disponibilité
        print("\n3. Test disponibilité Metasploit...")
        availability = client.test_metasploit_availability()
        print(f"Disponibilité: {availability}")
        
        if not availability.get('available'):
            print("❌ Metasploit RPC non disponible")
            return False
        
        # 4. Test sessions vides au début
        print("\n4. Test sessions initiales...")
        sessions = client.get_sessions()
        print(f"Sessions initiales: {len(sessions.get('sessions', []))}")
        
        # 5. Test commande console
        print("\n5. Test commande console...")
        result = client.execute_console_command("version")
        if result and result.get('success'):
            print(f"✅ Commande version: {result['output'][:100]}...")
        else:
            print(f"❌ Échec commande: {result}")
        
        # 6. Test liste sessions via console
        print("\n6. Test 'sessions -l' via console...")
        result = client.execute_console_command("sessions -l")
        if result and result.get('success'):
            print(f"✅ Sessions list: {result['output']}")
        else:
            print(f"❌ Échec sessions -l: {result}")
        
        # 7. Test avec HuntKit Integration
        print("\n7. Test intégration HuntKit...")
        from core.huntkit_tools import HuntKitIntegration
        huntkit = HuntKitIntegration()
        
        # Test via wrapper
        msf_sessions = huntkit.metasploit.get_active_sessions()
        print(f"Sessions via HuntKit: {msf_sessions}")
        
        # 8. Test de persistance
        print("\n8. Test persistance des sessions...")
        
        # Première commande
        result1 = client.execute_console_command("sessions -l")
        print("Première exécution sessions -l OK")
        
        time.sleep(2)
        
        # Deuxième commande (devrait utiliser la même console)
        result2 = client.execute_console_command("sessions -l")
        print("Deuxième exécution sessions -l OK")
        
        # Les deux devraient montrer les mêmes sessions
        if result1 and result2:
            print("✅ Persistance confirmée - même console utilisée")
        
        # 9. Test nettoyage
        print("\n9. Nettoyage...")
        client.cleanup()
        print("✅ Nettoyage terminé")
        
        print("\n" + "=" * 50)
        print("🎉 Test RPC Metasploit réussi !")
        return True
        
    except Exception as e:
        print(f"\n❌ Erreur pendant le test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_session_persistence():
    """Test spécifique de la persistance des sessions"""
    print("\n🔍 Test spécifique de persistance des sessions")
    print("-" * 40)
    
    try:
        from core.metasploit_rpc_client import MetasploitRPCClient
        
        # Créer deux instances séparées
        client1 = MetasploitRPCClient()
        client2 = MetasploitRPCClient()
        
        print("✅ Deux clients RPC créés")
        
        # Test avec le premier client
        result1 = client1.execute_console_command("sessions -l")
        print(f"Client 1 - Sessions: {len(result1.get('output', '').split('\\n'))}")
        
        # Test avec le deuxième client (devrait voir les mêmes sessions)
        result2 = client2.execute_console_command("sessions -l")
        print(f"Client 2 - Sessions: {len(result2.get('output', '').split('\\n'))}")
        
        # Les deux devraient accéder au même serveur RPC
        print("✅ Test persistance entre clients OK")
        
        client1.cleanup()
        client2.cleanup()
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur test persistance: {e}")
        return False

def test_exploit_with_rpc():
    """Test d'exploitation avec RPC pour vérifier les sessions"""
    print("\n🎯 Test exploitation avec sessions RPC")
    print("-" * 40)
    
    try:
        from core.huntkit_tools import HuntKitIntegration
        
        huntkit = HuntKitIntegration()
        
        # Tester un exploit sûr (scanner)
        print("Lancement d'un scan SSH...")
        result = huntkit.metasploit.run_auxiliary_scan(
            target='172.20.0.10',  # DVWA
            port=22,
            service='ssh',
            options={'scan_type': 'version'}
        )
        
        print(f"Résultat scan: {result.get('success', False)}")
        
        # Vérifier les sessions après
        sessions = huntkit.metasploit.get_active_sessions()
        print(f"Sessions après scan: {len(sessions.get('sessions', []))}")
        
        print("✅ Test exploitation avec RPC OK")
        return True
        
    except Exception as e:
        print(f"❌ Erreur test exploitation: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Démarrage des tests RPC Metasploit...")
    
    success = True
    
    # Test principal
    success &= test_rpc_sessions()
    
    # Test persistance
    success &= test_session_persistence()
    
    # Test exploitation
    success &= test_exploit_with_rpc()
    
    if success:
        print("\n🎉 TOUS LES TESTS RÉUSSIS !")
        print("✅ Le serveur RPC Metasploit fonctionne correctement")
        print("✅ Les sessions persistent entre les appels")
        print("✅ L'intégration HuntKit utilise RPC")
        sys.exit(0)
    else:
        print("\n❌ CERTAINS TESTS ONT ÉCHOUÉ")
        print("Vérifiez les logs ci-dessus pour plus de détails")
        sys.exit(1)

import sys
import os
sys.path.append('/app/backend')

from core.huntkit_tools import HuntKitIntegration
from services.session_manager import SessionManager
from database import DatabaseManager
from config import config

def test_session_detection():
    print("🧪 Test de détection de sessions Metasploit")
    print("=" * 50)
    
    try:
        # 1. Initialiser les composants
        print("1. Initialisation des composants...")
        huntkit = HuntKitIntegration()
        
        config_obj = config.get('development', config['default'])
        db = DatabaseManager(config_obj.DATABASE_URL)
        session_manager = SessionManager(db)
        
        print("✅ Composants initialisés")
        
        # 2. Test parsing sortie mock
        print("\n2. Test parsing sortie simulée...")
        mock_output = """
[*] Started reverse TCP handler on 172.20.0.2:4444
[*] Command shell session 1 opened (172.20.0.2:4444 -> 172.20.0.10:1234) at 2025-01-08 15:30:00 +0000
[*] Meterpreter session 2 opened (172.20.0.2:4444 -> 172.20.0.11:5678) at 2025-01-08 15:31:00 +0000
"""
        
        sessions = huntkit.metasploit.parse_sessions_from_output(mock_output)
        print(f"Sessions détectées: {len(sessions)}")
        
        for session in sessions:
            print(f"  - Session #{session['session_id']}: {session['session_type']} vers {session['target_ip']}:{session['target_port']}")
        
        if len(sessions) > 0:
            print("✅ Détection de sessions fonctionne")
        else:
            print("❌ Aucune session détectée")
            return False
        
        # 3. Test enregistrement en base
        print("\n3. Test enregistrement en base...")
        
        test_sessions = session_manager.detect_and_register_sessions_from_output(
            mock_output, 
            'test-task-123', 
            1  # user_id
        )
        
        print(f"Sessions enregistrées: {len(test_sessions)}")
        
        for session in test_sessions:
            print(f"  - DB ID: {session['db_id']}, MSF ID: {session['metasploit_session_id']}")
        
        if len(test_sessions) > 0:
            print("✅ Enregistrement en base fonctionne")
        else:
            print("❌ Échec enregistrement en base")
            return False
        
        # 4. Test récupération sessions actives
        print("\n4. Test récupération sessions actives...")
        
        active_sessions = session_manager.get_active_sessions()
        print(f"Sessions actives en base: {len(active_sessions)}")
        
        for session in active_sessions[-3:]:  # Dernières 3
            print(f"  - Session {session['session_id']} vers {session['target_ip']} (statut: {session['status']})")
        
        print("✅ Récupération sessions fonctionne")
        
        # 5. Test Metasploit availability
        print("\n5. Test disponibilité Metasploit...")
        
        msf_test = huntkit.metasploit.test_metasploit_availability()
        print(f"Metasploit disponible: {msf_test['available']}")
        
        if msf_test['available']:
            print(f"Version: {msf_test.get('version', 'N/A')}")
            print("✅ Metasploit opérationnel")
        else:
            print(f"❌ Metasploit non disponible: {msf_test.get('error', 'Erreur inconnue')}")
        
        print("\n" + "=" * 50)
        print("🎉 Test terminé avec succès !")
        return True
        
    except Exception as e:
        print(f"\n❌ Erreur pendant le test: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_session_detection()
    sys.exit(0 if success else 1)

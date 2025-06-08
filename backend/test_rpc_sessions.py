#!/usr/bin/env python3
"""
Script de test pour valider les corrections RPC
Utiliser: python backend/test_rpc_sessions_fixed.py
"""

import sys
import os
import time
sys.path.append('/app/backend')

def test_rpc_session_persistence():
    """Test complet de la persistance des sessions avec corrections"""
    print("🧪 Test RPC Sessions avec Corrections")
    print("=" * 60)
    
    try:
        # 1. Test import et initialisation
        print("1. Import et initialisation...")
        from core.metasploit_rpc_client import MetasploitRPCClient
        from core.huntkit_tools import HuntKitIntegration
        
        client = MetasploitRPCClient()
        huntkit = HuntKitIntegration()
        print("✅ Clients initialisés")
        
        # 2. Test disponibilité avec détails
        print("\n2. Test disponibilité Metasploit...")
        availability = client.test_metasploit_availability()
        print(f"📊 Disponibilité: {availability}")
        
        if not availability.get('available'):
            print("❌ Metasploit RPC non disponible - arrêt du test")
            return False
        
        # 3. Test sessions initiales (doit être vide ou contenir des sessions existantes)
        print("\n3. Test sessions initiales...")
        initial_sessions = client.get_sessions()
        print(f"📋 Sessions initiales: {len(initial_sessions.get('sessions', []))}")
        
        for session in initial_sessions.get('sessions', []):
            print(f"   🎯 Session #{session['session_id']}: {session['session_type']} -> {session['target_ip']}")
        
        # 4. Test commandes console de base
        print("\n4. Test commandes console...")
        commands_to_test = [
            "version",
            "sessions -l", 
            "show exploits | head -5"
        ]
        
        for cmd in commands_to_test:
            print(f"   🔧 Test: {cmd}")
            result = client.execute_console_command(cmd)
            if result and result.get('success'):
                output_preview = result['output'][:100].replace('\n', ' ')
                print(f"   ✅ OK: {output_preview}...")
            else:
                print(f"   ❌ Échec: {result}")
        
        # 5. Test spécifique aux sessions existantes
        print("\n5. Test interactions avec sessions existantes...")
        current_sessions = client.get_sessions()
        
        if current_sessions.get('sessions'):
            # Prendre la première session pour test
            test_session = current_sessions['sessions'][0]
            session_id = test_session['session_id']
            session_type = test_session['session_type']
            
            print(f"   🎯 Test sur session #{session_id} (type: {session_type})")
            
            # Test commande appropriée selon le type
            if session_type == 'meterpreter':
                test_command = 'sysinfo'
            else:
                test_command = 'whoami'
            
            print(f"   🔧 Exécution: {test_command}")
            cmd_result = client.execute_session_command(session_id, test_command)
            
            if cmd_result.get('success'):
                output = cmd_result.get('output', '')
                print(f"   ✅ Commande réussie: {output[:100]}...")
            else:
                print(f"   ❌ Commande échouée: {cmd_result.get('error')}")
        else:
            print("   ℹ️ Aucune session existante pour test")
        
        # 6. Test exploitation simple pour créer une session
        print("\n6. Test création de session via exploitation...")
        
        # Test avec un scanner SSH sûr
        print("   🔍 Lancement scan SSH sur DVWA...")
        exploit_result = huntkit.metasploit.run_auxiliary_scan(
            target='172.20.0.10',  # DVWA
            port=22,
            service='ssh',
            options={
                'scan_type': 'version',
                'THREADS': '1'
            }
        )
        
        print(f"   📊 Résultat exploitation: {exploit_result.get('success', False)}")
        
        # Vérifier si de nouvelles sessions ont été créées
        final_sessions = client.get_sessions()
        final_count = len(final_sessions.get('sessions', []))
        initial_count = len(initial_sessions.get('sessions', []))
        
        if final_count > initial_count:
            print(f"   🎉 Nouvelle(s) session(s) créée(s): {final_count - initial_count}")
            
            # Tester la nouvelle session
            new_sessions = final_sessions['sessions'][initial_count:]
            for new_session in new_sessions:
                session_id = new_session['session_id']
                print(f"   🎯 Test nouvelle session #{session_id}")
                
                # Test commande sur nouvelle session
                test_result = client.execute_session_command(session_id, 'pwd')
                if test_result.get('success'):
                    print(f"   ✅ Nouvelle session opérationnelle")
                else:
                    print(f"   ⚠️ Nouvelle session non interactive: {test_result.get('error')}")
        else:
            print(f"   ℹ️ Aucune nouvelle session créée (normal pour un scanner)")
        
        # 7. Test persistance entre appels
        print("\n7. Test persistance entre appels...")
        
        # Premier appel
        sessions_call1 = client.get_sessions()
        print(f"   📋 Premier appel: {len(sessions_call1.get('sessions', []))} sessions")
        
        time.sleep(2)
        
        # Deuxième appel (doit montrer les mêmes sessions)
        sessions_call2 = client.get_sessions()
        print(f"   📋 Deuxième appel: {len(sessions_call2.get('sessions', []))} sessions")
        
        # Comparer les IDs de sessions
        ids1 = {s['session_id'] for s in sessions_call1.get('sessions', [])}

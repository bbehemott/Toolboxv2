#!/usr/bin/env python3
"""
Script de validation technique - Intégration Metasploit Backend
Version corrigée et simplifiée
Usage: python metasploit_validation_fixed.py
"""

import sys
import os
import time
import json
import subprocess
from datetime import datetime

# Ajouter le chemin backend
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_metasploit_integration():
    """Test complet de l'intégration Metasploit"""
    
    print("🧪 VALIDATION METASPLOIT - VERSION CORRIGÉE")
    print("=" * 50)
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'tests': {},
        'success_count': 0,
        'total_tests': 0
    }
    
    def run_test(test_name, test_func):
        """Exécute un test et enregistre le résultat"""
        results['total_tests'] += 1
        print(f"\n📋 Test {results['total_tests']}: {test_name}...")
        
        try:
            result = test_func()
            if result.get('success', False):
                results['success_count'] += 1
                print("✅ SUCCÈS")
            else:
                print(f"❌ ÉCHEC: {result.get('error', 'Erreur inconnue')}")
            
            results['tests'][test_name.lower().replace(' ', '_')] = result
            return result
            
        except Exception as e:
            print(f"❌ EXCEPTION: {e}")
            results['tests'][test_name.lower().replace(' ', '_')] = {
                'success': False,
                'error': str(e)
            }
            return {'success': False, 'error': str(e)}
    
    # Test 1: Imports Python
    def test_imports():
        try:
            from core.huntkit_tools import HuntKitIntegration, MetasploitWrapper
            return {'success': True, 'message': 'Imports réussis'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 2: Initialisation HuntKit
    def test_huntkit_init():
        try:
            from core.huntkit_tools import HuntKitIntegration
            huntkit = HuntKitIntegration()
            has_metasploit = hasattr(huntkit, 'metasploit')
            return {
                'success': has_metasploit,
                'message': f'HuntKit initialisé, wrapper Metasploit: {has_metasploit}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 3: Détection Metasploit
    def test_metasploit_detection():
        try:
            from core.huntkit_tools import HuntKitIntegration
            huntkit = HuntKitIntegration()
            msf_test = huntkit.metasploit.test_metasploit_availability()
            
            return {
                'success': msf_test.get('available', False),
                'path': msf_test.get('path'),
                'version': msf_test.get('version'),
                'installation_type': msf_test.get('installation_type'),
                'error': msf_test.get('error') if not msf_test.get('available') else None
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 4: Statut des outils
    def test_tools_status():
        try:
            from core.huntkit_tools import HuntKitIntegration
            huntkit = HuntKitIntegration()
            tools_status = huntkit.get_tool_status()
            
            tools_available = tools_status.get('tools_available', {})
            metasploit_available = tools_available.get('msfconsole', False)
            
            return {
                'success': metasploit_available,
                'tools_count': len(tools_available),
                'metasploit_available': metasploit_available,
                'tools_available': tools_available
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 5: Recherche d'exploits
    def test_exploit_search():
        try:
            from core.huntkit_tools import HuntKitIntegration
            huntkit = HuntKitIntegration()
            
            search_result = huntkit.metasploit.search_exploits(service='ssh')
            
            if search_result.get('success'):
                exploits_count = len(search_result.get('exploits_found', []))
                return {
                    'success': True,
                    'exploits_found': exploits_count,
                    'search_query': search_result.get('search_query'),
                    'sample_exploits': search_result.get('exploits_found', [])[:3]
                }
            else:
                return {
                    'success': False,
                    'error': search_result.get('error', 'Recherche échouée')
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 6: Module auxiliaire
    def test_auxiliary_module():
        try:
            from core.huntkit_tools import HuntKitIntegration
            huntkit = HuntKitIntegration()
            
            aux_result = huntkit.metasploit.run_auxiliary_scan(
                target='127.0.0.1',
                port=22,
                service='ssh',
                options={'THREADS': '1', 'TIMEOUT': '5'}
            )
            
            return {
                'success': aux_result.get('success', False),
                'module': aux_result.get('module'),
                'scan_completed': aux_result.get('parsed_result', {}).get('scan_completed', False),
                'error': aux_result.get('error') if not aux_result.get('success') else None
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 7: Tâches Celery
    def test_celery_tasks():
        try:
            from celery_app import celery_app
            
            all_tasks = list(celery_app.tasks.keys())
            metasploit_tasks = [task for task in all_tasks if 'metasploit' in task or 'exploitation' in task]
            
            return {
                'success': len(metasploit_tasks) > 0,
                'total_tasks': len(all_tasks),
                'metasploit_tasks_count': len(metasploit_tasks),
                'metasploit_tasks': metasploit_tasks
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Test 8: Database
    def test_database():
        try:
            from database import DatabaseManager
            from config import config
            
            config_obj = config.get('development', config['default'])
            db = DatabaseManager(config_obj.DATABASE_URL)
            
            # Test de sauvegarde
            fake_task_id = f"test_metasploit_{int(time.time())}"
            
            db.save_module_result(
                task_id=fake_task_id,
                module_name='metasploit_validation_test',
                target='127.0.0.1:22',
                scan_type='validation',
                result_data={
                    'test': True,
                    'validation_time': datetime.now().isoformat()
                },
                scan_duration=1,
                stats={'test_stat': 1}
            )
            
            return {
                'success': True,
                'test_task_id': fake_task_id,
                'message': 'Sauvegarde test réussie'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # Exécution des tests
    run_test("Imports Python", test_imports)
    run_test("Initialisation HuntKit", test_huntkit_init)
    run_test("Détection Metasploit", test_metasploit_detection)
    run_test("Statut des outils", test_tools_status)
    run_test("Recherche d'exploits", test_exploit_search)
    run_test("Module auxiliaire", test_auxiliary_module)
    run_test("Tâches Celery", test_celery_tasks)
    run_test("Base de données", test_database)
    
    # Résumé final
    print("\n" + "=" * 50)
    print("📊 RÉSUMÉ DE LA VALIDATION")
    print("=" * 50)
    
    success_rate = (results['success_count'] / results['total_tests']) * 100
    
    print(f"Tests exécutés: {results['total_tests']}")
    print(f"Tests réussis: {results['success_count']}")
    print(f"Tests échoués: {results['total_tests'] - results['success_count']}")
    print(f"Taux de réussite: {success_rate:.1f}%")
    
    # Informations spécifiques
    metasploit_test = results['tests'].get('détection_metasploit', {})
    if metasploit_test.get('success'):
        print(f"\n🎯 METASPLOIT DÉTECTÉ:")
        print(f"   - Chemin: {metasploit_test.get('path', 'N/A')}")
        print(f"   - Version: {metasploit_test.get('version', 'N/A')}")
        print(f"   - Type: {metasploit_test.get('installation_type', 'N/A')}")
    
    # Tâches Celery
    celery_test = results['tests'].get('tâches_celery', {})
    if celery_test.get('success'):
        print(f"\n⚡ TÂCHES CELERY:")
        print(f"   - Total: {celery_test.get('total_tasks', 0)}")
        print(f"   - Metasploit: {celery_test.get('metasploit_tasks_count', 0)}")
        for task in celery_test.get('metasploit_tasks', []):
            print(f"     • {task}")
    
    # Recommandations
    print(f"\n💡 STATUT:")
    if success_rate == 100:
        print("✅ INTÉGRATION PARFAITE - Metasploit opérationnel !")
        print("   → Vous pouvez procéder au développement frontend")
    elif success_rate >= 80:
        print("⚠️ INTÉGRATION FONCTIONNELLE - Quelques ajustements possibles")
        print("   → Le cœur du système fonctionne")
    else:
        print("❌ INTÉGRATION INCOMPLÈTE - Corrections nécessaires")
        print("   → Vérifier les erreurs ci-dessus")
    
    # Sauvegarde du rapport
    try:
        report_filename = f"metasploit_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Rapport sauvegardé: {report_filename}")
    except Exception as e:
        print(f"\n⚠️ Impossible de sauvegarder le rapport: {e}")
    
    return results

if __name__ == "__main__":
    try:
        results = test_metasploit_integration()
        
        # Code de sortie selon le résultat
        success_rate = (results['success_count'] / results['total_tests']) * 100
        
        if success_rate == 100:
            sys.exit(0)  # Succès complet
        elif success_rate >= 80:
            sys.exit(1)  # Succès partiel
        else:
            sys.exit(2)  # Échec
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Validation interrompue par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Erreur critique lors de la validation: {e}")
        sys.exit(1)

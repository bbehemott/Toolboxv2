#!/usr/bin/env python3
"""
Script de test pour envoyer des logs GELF à Graylog
Cela créera les index nécessaires pour résoudre l'erreur Elasticsearch
"""

import json
import socket
import time
import gzip
from datetime import datetime

def send_gelf_message(host='localhost', port=12201, message_data=None):
    """Envoie un message GELF UDP vers Graylog"""
    
    if message_data is None:
        message_data = {
            "version": "1.1",
            "host": "toolbox-test",
            "short_message": "Test message from toolbox",
            "full_message": "Message de test complet pour vérifier la configuration GELF",
            "timestamp": time.time(),
            "level": 6,  # INFO
            "facility": "toolbox",
            "_application_name": "toolbox-test",
            "_environment": "development",
            "_test_type": "configuration"
        }
    
    try:
        # Convertir en JSON
        json_message = json.dumps(message_data)
        
        # Compresser le message
        compressed_message = gzip.compress(json_message.encode('utf-8'))
        
        # Envoyer via UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(compressed_message, (host, port))
        sock.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur envoi GELF: {e}")
        return False

def send_test_logs():
    """Envoie plusieurs messages de test pour différents outils"""
    
    print("📤 Envoi de messages de test GELF...")
    
    # Messages de test pour différents outils de pentest
    test_messages = [
        {
            "version": "1.1",
            "host": "toolbox-app",
            "short_message": "Application Flask démarrée",
            "timestamp": time.time(),
            "level": 6,
            "_application_name": "flask-app",
            "_component": "webapp"
        },
        {
            "version": "1.1", 
            "host": "toolbox-worker",
            "short_message": "Worker Celery prêt",
            "timestamp": time.time(),
            "level": 6,
            "_application_name": "celery-worker",
            "_component": "background-tasks"
        },
        {
            "version": "1.1",
            "host": "toolbox-scanner",
            "short_message": "Scan Nmap terminé avec succès",
            "full_message": "Scan Nmap sur 192.168.1.0/24 - 15 hôtes découverts",
            "timestamp": time.time(),
            "level": 6,
            "_application_name": "nmap",
            "_scan_type": "network_discovery",
            "_target": "192.168.1.0/24",
            "_hosts_found": 15
        },
        {
            "version": "1.1",
            "host": "toolbox-burp",
            "short_message": "Scan Burp Suite démarré",
            "full_message": "Scan de sécurité web avec Burp Suite Professional",
            "timestamp": time.time(),
            "level": 6,
            "_application_name": "burpsuite",
            "_scan_type": "web_security",
            "_target_url": "https://example.com"
        },
        {
            "version": "1.1",
            "host": "toolbox-zap",
            "short_message": "OWASP ZAP - Vulnérabilité détectée",
            "full_message": "XSS réfléchi détecté dans le paramètre 'search'",
            "timestamp": time.time(),
            "level": 4,  # WARNING
            "_application_name": "zap",
            "_vulnerability_type": "XSS",
            "_severity": "medium",
            "_url": "https://example.com/search?q=test"
        },
        {
            "version": "1.1",
            "host": "toolbox-msf",
            "short_message": "Metasploit - Exploitation réussie",
            "full_message": "Module exploit/windows/smb/ms17_010_eternalblue exécuté avec succès",
            "timestamp": time.time(),
            "level": 3,  # ERROR (critique pour pentest)
            "_application_name": "metasploit",
            "_exploit_module": "ms17_010_eternalblue",
            "_target_ip": "192.168.1.100",
            "_result": "success"
        }
    ]
    
    success_count = 0
    
    for i, message in enumerate(test_messages, 1):
        print(f"📤 Envoi message {i}/{len(test_messages)}: {message['short_message']}")
        
        if send_gelf_message(message_data=message):
            success_count += 1
            print(f"   ✅ Envoyé")
        else:
            print(f"   ❌ Échec")
        
        # Petit délai entre les messages
        time.sleep(0.5)
    
    print(f"\n📊 Résultat: {success_count}/{len(test_messages)} messages envoyés")
    
    if success_count > 0:
        print("\n⏳ Attendez 10-15 secondes puis rafraîchissez Graylog...")
        print("   Les index Elasticsearch vont être créés automatiquement.")
        return True
    else:
        print("\n❌ Aucun message envoyé - vérifiez la configuration GELF")
        return False

def main():
    print("🧪 Test d'envoi GELF pour résoudre l'erreur Elasticsearch")
    print("=" * 60)
    
    # Vérifier la connectivité
    print("🔍 Test de connectivité GELF...")
    test_message = {
        "version": "1.1",
        "host": "test-connectivity",
        "short_message": "Test de connectivité GELF",
        "timestamp": time.time(),
        "level": 6
    }
    
    if send_gelf_message(message_data=test_message):
        print("✅ Connectivité GELF OK")
        
        # Envoyer les messages de test
        if send_test_logs():
            print("\n🎯 Actions suivantes:")
            print("1. Attendez 10-15 secondes")
            print("2. Rafraîchissez la page Graylog (F5)")
            print("3. L'erreur 'index_not_found_exception' devrait disparaître")
            print("4. Vérifiez les messages dans Search")
            
            return True
        else:
            return False
    else:
        print("❌ Impossible de se connecter à GELF UDP:12201")
        print("\nVérifications:")
        print("- Graylog est-il démarré ? docker-compose ps graylog")
        print("- Port 12201 ouvert ? docker-compose logs graylog | grep 12201")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)

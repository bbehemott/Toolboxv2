#!/usr/bin/env python3
"""
Script de réparation Kibana - Génère des logs de sécurité
Copier-coller et lancer directement
"""

import json
import random
import time
import socket
import struct
import gzip
from datetime import datetime, timedelta
import threading

class KibanaFix:
    def __init__(self):
        self.graylog_host = "localhost"
        self.graylog_port = 12201
        
        # Données de test
        self.attack_types = ["brute_force", "port_scan", "web_attack", "sql_injection", "xss_attempt"]
        self.source_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10", "198.51.100.42"]
        self.services = ["ssh", "http", "https", "ftp", "mysql"]
        
    def send_gelf_message(self, message):
        """Envoyer un message GELF à Graylog"""
        try:
            # Créer le socket UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Convertir en JSON et compresser
            json_message = json.dumps(message)
            compressed = gzip.compress(json_message.encode('utf-8'))
            
            # Envoyer à Graylog
            sock.sendto(compressed, (self.graylog_host, self.graylog_port))
            sock.close()
            return True
        except Exception as e:
            print(f"❌ Erreur envoi: {e}")
            return False
    
    def generate_log(self):
        """Générer un log de sécurité"""
        now = datetime.now()
        attack_type = random.choice(self.attack_types)
        source_ip = random.choice(self.source_ips)
        service = random.choice(self.services)
        
        # Messages selon le type
        messages = {
            "brute_force": f"Failed login attempt from {source_ip}",
            "port_scan": f"Port scan from {source_ip}",
            "web_attack": f"Web attack from {source_ip}",
            "sql_injection": f"SQL injection from {source_ip}",
            "xss_attempt": f"XSS attempt from {source_ip}"
        }
        
        return {
            "version": "1.1",
            "host": "security-system",
            "short_message": messages[attack_type],
            "timestamp": now.timestamp(),
            "level": random.choice([1, 2, 3, 4]),  # 1=DEBUG, 2=INFO, 3=WARN, 4=ERROR
            "facility": "security",
            "_source_ip": source_ip,
            "_attack_type": attack_type,
            "_service": service,
            "_task": "security_monitoring"
        }
    
    def run(self):
        """Lancer la génération de logs"""
        print("🚀 DÉMARRAGE - Génération de logs de sécurité")
        print("=" * 50)
        
        # Vérifier la connexion
        print("🔍 Test de connexion Graylog...")
        test_log = self.generate_log()
        if self.send_gelf_message(test_log):
            print("✅ Connexion Graylog OK")
        else:
            print("❌ Impossible de se connecter à Graylog")
            print("Vérifiez que Graylog fonctionne sur localhost:12201")
            return
        
        # Générer 50 logs de test
        print("\n📝 Génération de logs de test...")
        success_count = 0
        
        for i in range(50):
            log = self.generate_log()
            if self.send_gelf_message(log):
                success_count += 1
                print(f"✅ Log {i+1}/50 envoyé")
            else:
                print(f"❌ Échec log {i+1}/50")
            
            # Petite pause pour éviter le spam
            time.sleep(0.1)
        
        print(f"\n🎯 RÉSULTAT: {success_count}/50 logs envoyés avec succès")
        
        # Instructions finales
        print("\n" + "=" * 50)
        print("📋 PROCHAINES ÉTAPES:")
        print("1. Attendre 2-3 minutes que Graylog traite les logs")
        print("2. Aller dans Kibana: http://localhost:5601")
        print("3. Créer l'index pattern 'graylog_*' avec @timestamp")
        print("4. Rafraîchir votre dashboard sécurité")
        print("\n✅ Script terminé - Kibana devrait maintenant fonctionner !")

# LANCEMENT AUTOMATIQUE DU SCRIPT
if __name__ == "__main__":
    fix = KibanaFix()
    fix.run()

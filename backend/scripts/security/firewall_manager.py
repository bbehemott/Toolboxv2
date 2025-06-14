#!/usr/bin/env python3
"""
Firewall Manager - Tâche 25
Gestion automatique des règles de filtrage et bannissement d'IPs
"""

import subprocess
import logging
import json
import time
import os
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import threading
import pickle

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FirewallManager')

class FirewallManager:
    def __init__(self, data_dir="/app/data"):
        self.data_dir = data_dir
        self.banned_ips_file = os.path.join(data_dir, "banned_ips.json")
        self.rules_file = os.path.join(data_dir, "firewall_rules.json")
        
        # Créer le répertoire de données si nécessaire
        os.makedirs(data_dir, exist_ok=True)
        
        # IPs bannies avec métadonnées
        self.banned_ips = self.load_banned_ips()
        
        # Configuration des durées de bannissement
        self.ban_durations = {
            'brute_force': 3600,    # 1 heure
            'port_scan': 1800,      # 30 minutes
            'web_attack': 7200,     # 2 heures
            'internal_access': 14400, # 4 heures
            'manual': 86400         # 24 heures
        }
        
        # Réseaux à ne jamais bannir (whitelist)
        self.whitelist_networks = [
            ipaddress.ip_network('127.0.0.0/8'),    # Localhost
            ipaddress.ip_network('172.20.0.0/16'),  # Réseau Docker
            ipaddress.ip_network('10.0.0.0/8'),     # Réseau privé
            ipaddress.ip_network('192.168.0.0/16')  # Réseau privé
        ]
        
        # Initialiser les règles de base
        self.setup_basic_firewall_rules()
        
        # Démarrer le thread de nettoyage automatique
        self.cleanup_thread = threading.Thread(target=self.auto_cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """Vérifier si une IP est dans la whitelist"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.whitelist_networks:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            logger.error(f"IP invalide: {ip}")
            return True  # En cas de doute, ne pas bannir
    
    def setup_basic_firewall_rules(self):
        """Configurer les règles de base du pare-feu"""
        logger.info("🔧 Configuration des règles de base du pare-feu...")
        
        basic_rules = [
            # Autoriser le trafic local
            "iptables -A INPUT -i lo -j ACCEPT",
            
            # Autoriser les connexions établies
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            
            # Autoriser SSH (avec rate limiting)
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH",
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            
            # Autoriser HTTP/HTTPS pour la toolbox
            "iptables -A INPUT -p tcp --dport 5000 -j ACCEPT",  # Toolbox App
            "iptables -A INPUT -p tcp --dport 9000 -j ACCEPT",  # Graylog
            "iptables -A INPUT -p tcp --dport 5601 -j ACCEPT",  # Kibana
            
            # Protéger les services internes (uniquement réseau Docker)
            "iptables -A INPUT -p tcp --dport 9200 -s 172.20.0.0/16 -j ACCEPT",  # Elasticsearch
            "iptables -A INPUT -p tcp --dport 9200 -j DROP",
            "iptables -A INPUT -p tcp --dport 27017 -s 172.20.0.0/16 -j ACCEPT", # MongoDB
            "iptables -A INPUT -p tcp --dport 27017 -j DROP",
            "iptables -A INPUT -p tcp --dport 6379 -s 172.20.0.0/16 -j ACCEPT",  # Redis
            "iptables -A INPUT -p tcp --dport 6379 -j DROP",
            "iptables -A INPUT -p tcp --dport 5432 -s 172.20.0.0/16 -j ACCEPT",  # PostgreSQL
            "iptables -A INPUT -p tcp --dport 5432 -j DROP"
        ]
        
        for rule in basic_rules:
            try:
                # Vérifier si la règle existe déjà pour éviter les doublons
                check_cmd = rule.replace("-A INPUT", "-C INPUT")
                result = subprocess.run(check_cmd.split(), capture_output=True, text=True)
                
                if result.returncode != 0:  # Règle n'existe pas
                    subprocess.run(rule.split(), check=True, capture_output=True)
                    logger.info(f"✅ Règle ajoutée: {rule}")
                else:
                    logger.info(f"⏩ Règle existe déjà: {rule}")
                    
            except subprocess.CalledProcessError as e:
                logger.warning(f"⚠️ Erreur règle {rule}: {e}")
            except Exception as e:
                logger.error(f"❌ Erreur règle {rule}: {e}")
    
    def ban_ip(self, ip: str, reason: str = "manual", duration: Optional[int] = None) -> bool:
        """Bannir une IP avec une durée spécifiée"""
        if self.is_ip_whitelisted(ip):
            logger.warning(f"⚠️ IP {ip} est whitelistée, bannissement ignoré")
            return False
        
        if ip in self.banned_ips:
            logger.info(f"⏩ IP {ip} déjà bannie")
            return True
        
        # Déterminer la durée de bannissement
        if duration is None:
            duration = self.ban_durations.get(reason, self.ban_durations['manual'])
        
        ban_until = datetime.now() + timedelta(seconds=duration)
        
        # Ajouter la règle iptables
        ban_rule = f"iptables -I INPUT 1 -s {ip} -j DROP"
        
        try:
            subprocess.run(ban_rule.split(), check=True, capture_output=True)
            
            # Enregistrer le bannissement
            self.banned_ips[ip] = {
                'banned_at': datetime.now().isoformat(),
                'ban_until': ban_until.isoformat(),
                'reason': reason,
                'duration': duration
            }
            
            self.save_banned_ips()
            
            logger.warning(f"🚨 IP BANNIE: {ip} (raison: {reason}, durée: {duration}s)")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Erreur bannissement {ip}: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Erreur bannissement {ip}: {e}")
            return False
    
    def unban_ip(self, ip: str) -> bool:
        """Débannir une IP"""
        if ip not in self.banned_ips:
            logger.info(f"⏩ IP {ip} n'est pas bannie")
            return True
        
        # Supprimer la règle iptables
        unban_rule = f"iptables -D INPUT -s {ip} -j DROP"
        
        try:
            subprocess.run(unban_rule.split(), check=True, capture_output=True)
            
            # Retirer de la liste des IPs bannies
            del self.banned_ips[ip]
            self.save_banned_ips()
            
            logger.info(f"✅ IP DÉBANNIE: {ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"⚠️ Règle peut-être inexistante pour {ip}: {e}")
            # Nettoyer quand même la liste
            if ip in self.banned_ips:
                del self.banned_ips[ip]
                self.save_banned_ips()
            return True
        except Exception as e:
            logger.error(f"❌ Erreur débannissement {ip}: {e}")
            return False
    
    def cleanup_expired_bans(self) -> int:
        """Nettoyer les bannissements expirés"""
        now = datetime.now()
        expired_ips = []
        
        for ip, ban_info in self.banned_ips.items():
            ban_until = datetime.fromisoformat(ban_info['ban_until'])
            if now > ban_until:
                expired_ips.append(ip)
        
        cleaned_count = 0
        for ip in expired_ips:
            if self.unban_ip(ip):
                cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"🧹 Nettoyage: {cleaned_count} IPs débannie(s) automatiquement")
        
        return cleaned_count
    
    def auto_cleanup_loop(self):
        """Boucle de nettoyage automatique en arrière-plan"""
        while True:
            try:
                time.sleep(300)  # Nettoyer toutes les 5 minutes
                self.cleanup_expired_bans()
            except Exception as e:
                logger.error(f"Erreur nettoyage automatique: {e}")
    
    def get_banned_ips_list(self) -> Dict:
        """Obtenir la liste des IPs bannies avec détails"""
        result = {
            'total': len(self.banned_ips),
            'active': 0,
            'expired': 0,
            'ips': []
        }
        
        now = datetime.now()
        
        for ip, ban_info in self.banned_ips.items():
            ban_until = datetime.fromisoformat(ban_info['ban_until'])
            is_active = now <= ban_until
            
            if is_active:
                result['active'] += 1
            else:
                result['expired'] += 1
            
            result['ips'].append({
                'ip': ip,
                'reason': ban_info['reason'],
                'banned_at': ban_info['banned_at'],
                'ban_until': ban_info['ban_until'],
                'is_active': is_active,
                'remaining_seconds': int((ban_until - now).total_seconds()) if is_active else 0
            })
        
        # Trier par date de bannissement (plus récent en premier)
        result['ips'].sort(key=lambda x: x['banned_at'], reverse=True)
        
        return result
    
    def get_firewall_stats(self) -> Dict:
        """Obtenir les statistiques du pare-feu"""
        try:
            # Compter les règles iptables
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], 
                                  capture_output=True, text=True)
            
            rules_count = len(result.stdout.split('\n')) - 3  # Exclure header/footer
            
            banned_stats = self.get_banned_ips_list()
            
            return {
                'iptables_rules': rules_count,
                'banned_ips_total': banned_stats['total'],
                'banned_ips_active': banned_stats['active'],
                'banned_ips_expired': banned_stats['expired'],
                'last_cleanup': datetime.now().isoformat(),
                'whitelist_networks': [str(net) for net in self.whitelist_networks]
            }
            
        except Exception as e:
            logger.error(f"Erreur stats pare-feu: {e}")
            return {'error': str(e)}
    
    def load_banned_ips(self) -> Dict:
        """Charger la liste des IPs bannies depuis le fichier"""
        try:
            if os.path.exists(self.banned_ips_file):
                with open(self.banned_ips_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Erreur chargement IPs bannies: {e}")
            return {}
    
    def save_banned_ips(self):
        """Sauvegarder la liste des IPs bannies"""
        try:
            with open(self.banned_ips_file, 'w') as f:
                json.dump(self.banned_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur sauvegarde IPs bannies: {e}")
    
    def emergency_unban_all(self) -> int:
        """Débannir toutes les IPs en urgence"""
        logger.warning("🚨 DÉBANNISSEMENT D'URGENCE DE TOUTES LES IPS")
        
        unbanned_count = 0
        for ip in list(self.banned_ips.keys()):
            if self.unban_ip(ip):
                unbanned_count += 1
        
        logger.warning(f"🚨 {unbanned_count} IPs débannie(s) en urgence")
        return unbanned_count

# Fonctions utilitaires pour l'API
def create_firewall_manager():
    """Créer une instance du gestionnaire de pare-feu"""
    return FirewallManager()

def ban_ip_from_threat(ip: str, threat_type: str, threat_count: int = 1):
    """Bannir une IP suite à une menace détectée"""
    fw = create_firewall_manager()
    reason = f"{threat_type}_{threat_count}"
    return fw.ban_ip(ip, reason=threat_type)

def get_security_status():
    """Obtenir le statut de sécurité complet"""
    fw = create_firewall_manager()
    return {
        'firewall_stats': fw.get_firewall_stats(),
        'banned_ips': fw.get_banned_ips_list(),
        'timestamp': datetime.now().isoformat()
    }

if __name__ == "__main__":
    # Test du module
    print("🛡️ TEST FIREWALL MANAGER")
    print("=" * 30)
    
    fw = FirewallManager()
    
    # Test bannissement
    test_ip = "198.51.100.1"  # IP de test (RFC5737)
    print(f"🧪 Test bannissement IP: {test_ip}")
    
    if fw.ban_ip(test_ip, "test", 60):
        print("✅ Bannissement réussi")
        
        # Attendre un peu
        time.sleep(2)
        
        # Vérifier stats
        stats = fw.get_firewall_stats()
        print(f"📊 Stats: {stats}")
        
        # Débannir
        if fw.unban_ip(test_ip):
            print("✅ Débannissement réussi")
    
    print("✅ Test terminé")

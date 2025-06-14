#!/usr/bin/env python3
"""
API Flask Sécurité + Webhook
Connexion finale Graylog → FirewallManager
"""

from flask import Blueprint, request, jsonify, render_template
import logging
import json
import re
import os
import sys
from datetime import datetime

# Ajouter le chemin vers le FirewallManager
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'security'))

try:
    from firewall_manager import FirewallManager, get_security_status
except ImportError:
    # Fallback si pas trouvé
    class FirewallManager:
        def ban_ip(self, ip, reason, duration=None):
            print(f"SIMULATION: Bannir {ip} pour {reason}")
            return True
        def get_firewall_stats(self):
            return {"simulation": True}
    
    def get_security_status():
        return {"status": "simulation"}

# Configuration logging
logger = logging.getLogger('SecurityAPI')

# Blueprint Flask
security_bp = Blueprint('security', __name__, url_prefix='/api/security')

def extract_ip_from_alert(alert_data):
    """Extraire l'IP source depuis les données d'alerte Graylog"""
    
    # Méthode 1: Champ direct
    if 'source_ip' in alert_data:
        return alert_data['source_ip']
    
    # Méthode 2: Dans les champs de l'événement
    if 'event' in alert_data and 'fields' in alert_data['event']:
        fields = alert_data['event']['fields']
        if 'source_ip' in fields:
            return fields['source_ip']
    
    # Méthode 3: Extraire du message
    message = ""
    if 'message' in alert_data:
        message = alert_data['message']
    elif 'event' in alert_data and 'message' in alert_data['event']:
        message = alert_data['event']['message']
    
    if message:
        # Pattern IP standard
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, message)
        
        # Filtrer les IPs privées/locales
        for ip in ips:
            if not ip.startswith(('127.', '172.20.', '10.', '192.168.')):
                return ip
        
        # Si que des IPs privées, prendre la première quand même
        if ips:
            return ips[0]
    
    return None

def determine_threat_type(alert_data):
    """Déterminer le type de menace depuis l'alerte"""
    
    # Récupérer le titre de l'alerte
    title = ""
    if 'alert_type' in alert_data:
        title = alert_data['alert_type'].lower()
    elif 'event_definition_title' in alert_data:
        title = alert_data['event_definition_title'].lower()
    elif 'title' in alert_data:
        title = alert_data['title'].lower()
    
    # Déterminer le type selon le titre
    if 'brute' in title or 'force' in title:
        return 'brute_force'
    elif 'port' in title or 'scan' in title:
        return 'port_scan'
    elif 'web' in title or 'attack' in title:
        return 'web_attack'
    elif 'internal' in title or 'access' in title:
        return 'internal_access'
    else:
        return 'unknown'

@security_bp.route('/webhook', methods=['POST'])
def graylog_webhook():
    """Webhook pour recevoir les alertes Graylog et déclencher les actions"""
    
    try:
        # Récupérer les données JSON
        alert_data = request.get_json()
        
        if not alert_data:
            logger.warning("⚠️ Webhook reçu sans données JSON")
            return jsonify({'status': 'error', 'message': 'No JSON data'}), 400
        
        logger.info(f"🚨 ALERTE REÇUE: {json.dumps(alert_data, indent=2)}")
        
        # Extraire l'IP source
        source_ip = extract_ip_from_alert(alert_data)
        if not source_ip:
            logger.warning("⚠️ Impossible d'extraire l'IP source de l'alerte")
            return jsonify({
                'status': 'warning', 
                'message': 'No source IP found',
                'alert_logged': True
            }), 200
        
        # Déterminer le type de menace
        threat_type = determine_threat_type(alert_data)
        
        logger.warning(f"🚨 MENACE DÉTECTÉE: {threat_type} depuis {source_ip}")
        
        # Déclencher le bannissement
        fw = FirewallManager()
        ban_result = fw.ban_ip(source_ip, threat_type)
        
        if ban_result:
            logger.warning(f"✅ IP {source_ip} BANNIE automatiquement pour {threat_type}")
            
            # Logger l'action dans Graylog (optionnel)
            log_security_action(source_ip, threat_type, 'banned', alert_data)
            
            return jsonify({
                'status': 'success',
                'action': 'ip_banned',
                'ip': source_ip,
                'threat_type': threat_type,
                'timestamp': datetime.now().isoformat()
            }), 200
        else:
            logger.error(f"❌ Échec bannissement {source_ip}")
            return jsonify({
                'status': 'error',
                'message': 'Ban failed',
                'ip': source_ip
            }), 500
            
    except Exception as e:
        logger.error(f"❌ Erreur webhook: {e}")
        return jsonify({
            'status': 'error', 
            'message': str(e)
        }), 500

@security_bp.route('/status', methods=['GET'])
def security_status():
    """Obtenir le statut complet de la sécurité"""
    
    try:
        status = get_security_status()
        return jsonify({
            'status': 'success',
            'data': status
        }), 200
    except Exception as e:
        logger.error(f"Erreur status sécurité: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@security_bp.route('/banned-ips', methods=['GET'])
def get_banned_ips():
    """Obtenir la liste des IPs bannies"""
    
    try:
        fw = FirewallManager()
        banned_list = fw.get_banned_ips_list()
        
        return jsonify({
            'status': 'success',
            'data': banned_list
        }), 200
    except Exception as e:
        logger.error(f"Erreur liste IPs bannies: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@security_bp.route('/ban-ip', methods=['POST'])
def manual_ban_ip():
    """Bannir une IP manuellement"""
    
    try:
        data = request.get_json()
        ip = data.get('ip')
        reason = data.get('reason', 'manual')
        duration = data.get('duration')
        
        if not ip:
            return jsonify({
                'status': 'error',
                'message': 'IP address required'
            }), 400
        
        fw = FirewallManager()
        result = fw.ban_ip(ip, reason, duration)
        
        if result:
            logger.info(f"✅ IP {ip} bannie manuellement")
            return jsonify({
                'status': 'success',
                'action': 'ip_banned',
                'ip': ip,
                'reason': reason
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Ban failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur bannissement manuel: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@security_bp.route('/unban-ip', methods=['POST'])
def manual_unban_ip():
    """Débannir une IP manuellement"""
    
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({
                'status': 'error',
                'message': 'IP address required'
            }), 400
        
        fw = FirewallManager()
        result = fw.unban_ip(ip)
        
        if result:
            logger.info(f"✅ IP {ip} débannie manuellement")
            return jsonify({
                'status': 'success',
                'action': 'ip_unbanned',
                'ip': ip
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Unban failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur débannissement manuel: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@security_bp.route('/firewall-stats', methods=['GET'])
def get_firewall_stats():
    """Obtenir les statistiques du pare-feu"""
    
    try:
        fw = FirewallManager()
        stats = fw.get_firewall_stats()
        
        return jsonify({
            'status': 'success',
            'data': stats
        }), 200
    except Exception as e:
        logger.error(f"Erreur stats pare-feu: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def log_security_action(ip, threat_type, action, original_alert):
    """Logger une action de sécurité pour audit"""
    
    security_log = {
        'timestamp': datetime.now().isoformat(),
        'event_type': 'security_action',
        'source_ip': ip,
        'threat_type': threat_type,
        'action': action,
        'original_alert': original_alert,
        'system': 'toolbox_security_webhook'
    }
    
    # Pour l'instant, juste logger localement
    logger.info(f"📝 ACTION SÉCURITÉ: {json.dumps(security_log)}")
    
    # TODO: Envoyer vers Graylog GELF si nécessaire
    
# Route de test pour vérifier que l'API fonctionne
@security_bp.route('/test', methods=['GET', 'POST'])
def test_webhook():
    """Endpoint de test pour vérifier le webhook"""
    
    if request.method == 'POST':
        test_alert = {
            'alert_type': 'Test Brute Force Attack',
            'source_ip': '203.0.113.1',  # IP de test RFC5737
            'message': 'Test alert from 203.0.113.1',
            'timestamp': datetime.now().isoformat()
        }
        
        return graylog_webhook()
    else:
        return jsonify({
            'status': 'success',
            'message': 'Security API is working',
            'endpoints': [
                '/webhook (POST) - Recevoir alertes Graylog',
                '/status (GET) - Statut sécurité',
                '/banned-ips (GET) - Liste IPs bannies',
                '/ban-ip (POST) - Bannir IP manuellement',
                '/unban-ip (POST) - Débannir IP',
                '/firewall-stats (GET) - Stats pare-feu',
                '/test (GET/POST) - Test webhook'
            ]
        }), 200

# Enregistrer le blueprint dans votre app principale
def register_security_api(app):
    """Enregistrer l'API sécurité dans l'application Flask"""
    app.register_blueprint(security_bp)
    logger.info("✅ API Sécurité enregistrée: /api/security/*")

if __name__ == "__main__":
    # Test standalone
    from flask import Flask
    
    app = Flask(__name__)
    register_security_api(app)
    
    print("🧪 Test API Sécurité...")
    print("Endpoints disponibles:")
    print("- GET  /api/security/test")
    print("- POST /api/security/webhook")
    print("- GET  /api/security/status")
    
    app.run(host='0.0.0.0', port=5001, debug=True)

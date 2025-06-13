# backend/api/traffic.py
"""
API Flask pour les tâches 20 et 45 - Traffic Analysis
Routes pour l'interface web
"""

from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
import os
import tempfile
from api.traffic_analysis import TrafficAnalysisModule
from auth import login_required
import logging

logger = logging.getLogger('toolbox.traffic')

traffic_bp = Blueprint('traffic', __name__)
analyzer = TrafficAnalysisModule()

# =============================================================================
# PAGE PRINCIPALE 
# =============================================================================

@traffic_bp.route('/')
@login_required
def traffic_page():
    """Page principale du module traffic"""
    return render_template('traffic/traffic_analysis.html')

# =============================================================================
# API TÂCHE 20 - CAPTURE PENTEST
# =============================================================================

@traffic_bp.route('/api/pentest-capture', methods=['POST'])
@login_required
def api_pentest_capture():
    """Tâche 20 : Lancer capture pendant pentest"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        duration = int(data.get('duration', 60))
        
        # Validation basique
        if not target:
            return jsonify({'success': False, 'error': 'Cible manquante'})
        
        if duration < 10 or duration > 600:  # Entre 10s et 10min
            return jsonify({'success': False, 'error': 'Durée invalide (10-600s)'})
        
        logger.info(f"🔍 Tâche 20 - Capture {target} pendant {duration}s")
        
        # Lancer la capture
        result = analyzer.pentest_capture(target, duration)
        
        if result['success']:
            logger.info(f"✅ Capture réussie: {result.get('packets_captured', 0)} paquets")
        else:
            logger.error(f"❌ Échec capture: {result.get('error')}")
        
        return jsonify(result)
        
    except ValueError as e:
        return jsonify({'success': False, 'error': f'Paramètre invalide: {e}'})
    except Exception as e:
        logger.error(f"Erreur capture pentest: {e}")
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# API TÂCHE 45 - ANALYSE FORENSIQUE
# =============================================================================

@traffic_bp.route('/api/forensic-analysis', methods=['POST'])
@login_required  
def api_forensic_analysis():
    """Tâche 45 : Analyse forensique PCAP"""
    try:
        # Cas 1: Upload de fichier
        if 'pcap_file' in request.files:
            uploaded_file = request.files['pcap_file']
            
            if uploaded_file.filename == '':
                return jsonify({'success': False, 'error': 'Aucun fichier sélectionné'})
            
            # Vérifier extension
            if not uploaded_file.filename.lower().endswith(('.pcap', '.pcapng')):
                return jsonify({'success': False, 'error': 'Format invalide (requis: .pcap/.pcapng)'})
            
            # Sauver temporairement
            filename = secure_filename(uploaded_file.filename)
            temp_path = os.path.join('/tmp', f'upload_{filename}')
            uploaded_file.save(temp_path)
            
            logger.info(f"🕵️ Tâche 45 - Analyse upload: {filename}")
            result = analyzer.forensic_analysis(temp_path)
            
            # Nettoyer le fichier temporaire
            try:
                os.remove(temp_path)
            except:
                pass
                
        # Cas 2: Analyse d'un fichier existant (depuis Tâche 20)
        elif request.is_json:
            data = request.get_json()
            pcap_file = data.get('pcap_file', '').strip()
            
            if not pcap_file:
                return jsonify({'success': False, 'error': 'Chemin fichier manquant'})
            
            logger.info(f"🕵️ Tâche 45 - Analyse fichier: {pcap_file}")
            result = analyzer.forensic_analysis(pcap_file)
            
        else:
            return jsonify({'success': False, 'error': 'Données manquantes'})
        
        if result['success']:
            logger.info(f"✅ Analyse forensique réussie")
        else:
            logger.error(f"❌ Échec analyse: {result.get('error')}")
            
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Erreur analyse forensique: {e}")
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# TÉLÉCHARGEMENT PCAP
# =============================================================================

@traffic_bp.route('/api/download/<path:filename>')
@login_required
def download_pcap(filename):
    """Télécharger un fichier PCAP"""
    try:
        # Sécurité: vérifier que le fichier est dans /app/data/pcap et existe
        safe_filename = secure_filename(filename)
        file_path = f'/app/data/pcap/{safe_filename}'
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'Fichier introuvable'}), 404
        
        return send_file(file_path, as_attachment=True, download_name=safe_filename)
        
    except Exception as e:
        logger.error(f"Erreur téléchargement: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# STATUS ET INFORMATIONS
# =============================================================================

@traffic_bp.route('/api/status')
@login_required
def traffic_status():
    """Status du module traffic"""
    try:
        # Vérifier si tshark est disponible
        import subprocess
        result = subprocess.run(['which', 'tshark'], capture_output=True)
        tshark_available = result.returncode == 0
        
        # Lister fichiers PCAP récents
        pcap_files = []
        try:
            for file in os.listdir('/app/data/pcap'):
                if file.endswith('.pcap') and file.startswith('pentest_'):
                    file_path = f'/app/data/pcap/{file}'
                    stat = os.stat(file_path)
                    pcap_files.append({
                        'filename': file,
                        'size': stat.st_size,
                        'created': stat.st_ctime
                    })
        except:
            pass
        
        return jsonify({
            'success': True,
            'tshark_available': tshark_available,
            'recent_captures': sorted(pcap_files, key=lambda x: x['created'], reverse=True)[:5]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# GESTION DES CAPTURES UTILISATEUR
# =============================================================================

@traffic_bp.route('/api/user-captures')
@login_required
def api_user_captures():
    """Liste des captures de l'utilisateur"""
    try:
        from flask import session
        user_id = session.get('user_id')
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Utilisateur non identifié'})
        
        pcaps = analyzer.pcap_manager.list_user_pcaps(user_id)
        
        return jsonify({
            'success': True,
            'captures': pcaps
        })
        
    except Exception as e:
        logger.error(f"Erreur liste captures: {e}")
        return jsonify({'success': False, 'error': str(e)})

logger.info("🌐 Module Traffic API chargé - Tâches 20 & 45 prêtes")

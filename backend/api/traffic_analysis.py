# backend/api/traffic_analysis.py
"""
Module traffic analysis - Version intégrée avec votre toolbox
Tâches 20 & 45 - Base commune + interfaces spécialisées
"""

import subprocess
import os
import json
import logging
from api.pcap_manager import PcapFileManager

logger = logging.getLogger('toolbox.traffic')

class TrafficAnalysisModule:
    """Module traffic intégré avec votre architecture"""
    
    def __init__(self):
        self.pcap_manager = PcapFileManager()
        
        # Vérifier si tshark est disponible
        self.tshark_available = self._check_tshark()
        if not self.tshark_available:
            logger.warning("⚠️ tshark non disponible - Fonctionnalités limitées")
    
    def _check_tshark(self):
        """Vérifier disponibilité tshark"""
        try:
            result = subprocess.run(['which', 'tshark'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def pentest_capture(self, target, duration=60):
        """Tâche 20 - Capture intégrée"""
        
        if not self.tshark_available:
            return {'success': False, 'error': 'tshark non disponible'}
        
        # Utiliser répertoire sécurisé
        temp_pcap = f"/tmp/capture_{target.replace('.', '_').replace('/', '_')}_{os.getpid()}.pcap"
        
        try:
            # Commande tshark avec gestion d'erreurs
            command = [
                'tshark', '-i', 'any',
                '-a', f'duration:{duration}',
                '-f', f'net {target.split(".")[0]}.{target.split(".")[1]}.0.0/16',
                '-w', temp_pcap
            ]
            logger.info(f"📦 Commande exacte: {' '.join(command)}")
            logger.info(f"📁 Fichier temp: {temp_pcap}")
        try:
            # ... code ...
            result = subprocess.run(command, capture_output=True, text=True, timeout=duration+10)
        
            # ✅ CES LIGNES DOIVENT ÊTRE INDENTÉES
            logger.info(f"🔍 Return code: {result.returncode}")
            logger.info(f"📤 STDOUT: {result.stdout}")
            logger.info(f"❌ STDERR: {result.stderr}")

            logger.info(f"🔍 Début capture {target} pendant {duration}s")
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True,
                timeout=duration + 10
            )
            
            if os.path.exists(temp_pcap) and os.path.getsize(temp_pcap) > 0:
                # Sauvegarder de manière sécurisée
                secure_pcap = self.pcap_manager.save_pcap(
                    temp_pcap, 
                    f"pentest_{target}"
                )
                
                # Nettoyer temp
                os.remove(temp_pcap)
                
                # Stats rapides
                stats = self._get_capture_stats(secure_pcap)
                
                logger.info(f"✅ Capture réussie: {stats.get('packets', 0)} paquets")
                
                return {
                    'success': True,
                    'pcap_file': secure_pcap,
                    'target': target,
                    'duration': duration,
                    'packets_captured': stats.get('packets', 0)
                }
            else:
                return {
                    'success': False,
                    'error': f'Aucun trafic capturé pour {target}'
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout capture'}
        except Exception as e:
            logger.error(f"Erreur capture: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            # Nettoyer fichier temp si il reste
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)
    
    def forensic_analysis(self, pcap_reference):
        """Tâche 45 - Analyse forensique intégrée"""
        
        # Récupérer fichier de manière sécurisée
        pcap_file = self.pcap_manager.get_pcap(pcap_reference)
        
        if not pcap_file:
            return {'success': False, 'error': 'Fichier PCAP inaccessible'}
        
        try:
            logger.info(f"🕵️ Début analyse forensique: {pcap_reference}")
            
            # Analyse complète
            general_info = self._get_general_info(pcap_file)
            protocols = self._get_protocols(pcap_file)
            conversations = self._get_conversations(pcap_file)
            
            logger.info(f"✅ Analyse terminée: {len(protocols)} protocoles, {len(conversations)} conversations")
            
            return {
                'success': True,
                'pcap_file': pcap_reference,  # Référence originale
                'general_info': general_info,
                'protocols': protocols,
                'conversations': conversations
            }
            
        except Exception as e:
            logger.error(f"Erreur analyse forensique: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_capture_stats(self, pcap_file):
        """Stats PCAP - Gestion sécurisée"""
        
        # Si c'est une référence MinIO, télécharger temporairement
        if pcap_file.startswith("minio://"):
            temp_file = self.pcap_manager.get_pcap(pcap_file)
            if not temp_file:
                return {'packets': 0}
            pcap_file = temp_file
        
        try:
            command = ['tshark', '-r', pcap_file, '-q', '-z', 'io,stat,0']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'frames' in line.lower():
                        try:
                            packets = int(line.split()[1])
                            return {'packets': packets}
                        except:
                            pass
            
            return {'packets': 0}
            
        except Exception as e:
            logger.error(f"Erreur stats PCAP: {e}")
            return {'packets': 0}
    
    def _get_general_info(self, pcap_file):
        """Infos de base du fichier PCAP"""
        try:
            command = ['capinfos', pcap_file]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            info = {}
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Number of packets' in line:
                        info['total_packets'] = line.split(':')[1].strip()
                    elif 'File size' in line:
                        info['file_size'] = line.split(':')[1].strip()
                    elif 'Data size' in line:
                        info['data_size'] = line.split(':')[1].strip()
                    elif 'Capture duration' in line:
                        info['duration'] = line.split(':')[1].strip()
            
            return info
            
        except Exception as e:
            logger.error(f"Erreur infos générales: {e}")
            return {}
    
    def _get_protocols(self, pcap_file):
        """Liste des protocoles dans le PCAP"""
        try:
            command = ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs']
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            protocols = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'frames' in line and 'bytes' in line and line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            protocol = parts[0]
                            frames = parts[1]
                            if protocol not in ['eth', 'frame']:  # Filtrer protocoles de base
                                protocols.append({
                                    'protocol': protocol, 
                                    'frames': frames
                                })
            
            return protocols[:10]  # Top 10 protocoles
            
        except Exception as e:
            logger.error(f"Erreur analyse protocoles: {e}")
            return []
    
    def _get_conversations(self, pcap_file):
        """Conversations IP principales"""
        try:
            command = ['tshark', '-r', pcap_file, '-q', '-z', 'conv,ip']
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            conversations = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '<->' in line and line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            conversations.append({
                                'endpoints': parts[0],
                                'packets': parts[1],
                                'bytes': parts[2]
                            })
            
            return conversations[:5]  # Top 5 conversations
            
        except Exception as e:
            logger.error(f"Erreur analyse conversations: {e}")
            return []

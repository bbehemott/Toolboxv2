"""
Module traffic analysis - Version intégrée avec votre toolbox
"""

import subprocess
import os
import json
from api.pcap_manager import PcapFileManager

class TrafficAnalysisModule:
    """Module traffic intégré avec votre architecture"""
    
    def __init__(self):
        self.pcap_manager = PcapFileManager()
        
        # Vérifier si tshark est disponible
        self.tshark_available = self._check_tshark()
        if not self.tshark_available:
            raise RuntimeError("tshark non disponible - Installer wireshark-common")
    
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
        temp_pcap = f"/tmp/capture_{target.replace('.', '_')}_{os.getpid()}.pcap"
        
        try:
            # Commande tshark avec gestion d'erreurs
            command = [
                'timeout', str(duration),
                'tshark', '-i', 'any', 
                '-f', f'host {target}',
                '-w', temp_pcap
            ]
            
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
            # Analyse comme avant mais avec fichier sécurisé
            general_info = self._get_general_info(pcap_file)
            protocols = self._get_protocols(pcap_file)
            conversations = self._get_conversations(pcap_file)
            
            return {
                'success': True,
                'pcap_file': pcap_reference,  # Référence originale
                'general_info': general_info,
                'protocols': protocols,
                'conversations': conversations
            }
            
        except Exception as e:
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
    
    # Autres méthodes restent identiques...
    def _get_general_info(self, pcap_file):
        # Identique à avant
        pass
    
    def _get_protocols(self, pcap_file):
        # Identique à avant  
        pass
    
    def _get_conversations(self, pcap_file):
        # Identique à avant
        pass

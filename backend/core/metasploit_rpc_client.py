import os
import time
import json
import logging
import subprocess
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime
import re

logger = logging.getLogger(__name__)

# Import conditionnel des dépendances RPC
try:
    import msgpack
    import requests
    RPC_AVAILABLE = True
except ImportError:
    logger.warning("⚠️ msgpack et requests requis pour RPC - installation: pip install msgpack requests")
    RPC_AVAILABLE = False

class MetasploitRPCClient:
    """Client RPC persistant pour Metasploit Framework"""
    
    def __init__(self, host='127.0.0.1', port=55552, username='msf', password='msfrpc123', ssl=False):
        if not RPC_AVAILABLE:
            raise ImportError("msgpack et requests requis pour le client RPC")
        
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        
        # État de connexion
        self.token = None
        self.authenticated = False
        
        # URL de base
        self.base_url = f"{'https' if ssl else 'http'}://{host}:{port}/api/"
        
        # État des consoles
        self.console_id = None
        
        # Lock pour thread safety
        self._lock = threading.Lock()
        
        # Processus RPC
        self._rpc_process = None
        
        # Initialiser le serveur
        self._ensure_rpc_server()
    
    def _ensure_rpc_server(self):
        """Démarre le serveur RPC Metasploit de façon persistante"""
        try:
            # Vérifier si un serveur RPC existe déjà
            if self._test_connection():
                logger.info("🎯 Serveur RPC Metasploit déjà actif")
                return True
            
            logger.info("🚀 Démarrage du serveur RPC Metasploit...")
            
            # Trouver msfrpcd
            msfrpcd_path = self._find_msfrpcd()
            if not msfrpcd_path:
                logger.error("❌ msfrpcd non trouvé")
                return False
            
            # Commande pour démarrer msfrpcd
            cmd = [
                msfrpcd_path, 
                '-U', self.username,
                '-P', self.password,
                '-p', str(self.port),
                '-a', self.host,
                '-f'  # Foreground
            ]
            
            if not self.ssl:
                cmd.append('-n')  # Pas de SSL
            
            logger.info(f"🔧 Commande RPC: {' '.join(cmd)}")
            
            # Démarrer le processus en arrière-plan
            self._rpc_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            # Attendre que le serveur soit prêt
            for i in range(15):  # 15 secondes max
                time.sleep(1)
                if self._test_connection():
                    logger.info(f"✅ Serveur RPC prêt après {i+1}s")
                    return True
                
                if i == 5:  # Log après 5s
                    logger.info("⏳ Serveur RPC en cours de démarrage...")
            
            logger.error("❌ Timeout: Serveur RPC non démarré")
            return False
            
        except Exception as e:
            logger.error(f"❌ Erreur démarrage RPC: {e}")
            return False
    
    def _find_msfrpcd(self):
        """Trouve le binaire msfrpcd"""
        possible_paths = [
            '/opt/metasploit-framework/embedded/framework/msfrpcd',
            '/opt/metasploit-framework/msfrpcd',
            '/usr/local/bin/msfrpcd',
            '/usr/bin/msfrpcd'
        ]
        
        for path in possible_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                logger.info(f"🔧 msfrpcd trouvé: {path}")
                return path
        
        # Essayer avec 'which'
        try:
            result = subprocess.run(['which', 'msfrpcd'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                path = result.stdout.strip()
                logger.info(f"🔧 msfrpcd trouvé via which: {path}")
                return path
        except:
            pass
        
        logger.error("❌ msfrpcd non trouvé dans les chemins standards")
        return None
    
    def _test_connection(self):
        """Test rapide de connexion au serveur RPC"""
        try:
            response = requests.get(
                f"{self.base_url}",
                timeout=3,
                verify=False
            )
            return response.status_code in [200, 401, 404]
        except:
            return False
    
    def authenticate(self):
        """Authentification au serveur RPC"""
        try:
            if not RPC_AVAILABLE:
                return False
            
            data = msgpack.packb(['auth.login', self.username, self.password])
            
            response = requests.post(
                self.base_url,
                data=data,
                headers={'Content-Type': 'binary/message-pack'},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = msgpack.unpackb(response.content, raw=False)
                
                if 'token' in result:
                    self.token = result['token']
                    self.authenticated = True
                    logger.info("✅ Authentification RPC réussie")
                    
                    # Créer une console persistante
                    self._create_console()
                    return True
                else:
                    logger.error(f"❌ Pas de token dans la réponse: {result}")
            else:
                logger.error(f"❌ Échec auth RPC: HTTP {response.status_code}")
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Erreur authentification: {e}")
            return False
    
    def _create_console(self):
        """Crée une console Metasploit persistante"""
        try:
            result = self.call('console.create')
            if result and 'id' in result:
                self.console_id = result['id']
                logger.info(f"✅ Console persistante créée: {self.console_id}")
                return True
            
            logger.error("❌ Impossible de créer la console")
            return False
            
        except Exception as e:
            logger.error(f"❌ Erreur création console: {e}")
            return False
    
    def call(self, method, *args):
        """Appel RPC générique avec authentification automatique"""
        if not RPC_AVAILABLE:
            return None
        
        if not self.authenticated:
            if not self.authenticate():
                return None
        
        try:
            # Construire la requête RPC
            data = msgpack.packb([method, self.token] + list(args))
            
            response = requests.post(
                self.base_url,
                data=data,
                headers={'Content-Type': 'binary/message-pack'},
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                result = msgpack.unpackb(response.content, raw=False)
                return result
            else:
                logger.error(f"❌ Erreur RPC HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Erreur appel RPC {method}: {e}")
            return None
    
    def execute_console_command(self, command):
        """Exécute une commande dans la console persistante"""
        if not self.console_id:
            logger.error("❌ Aucune console disponible")
            return None
        
        try:
            with self._lock:  # Thread safety
                # Envoyer la commande
                self.call('console.write', self.console_id, command + '\n')
                
                # Attendre et lire la réponse
                time.sleep(1)
                
                output = ""
                for _ in range(10):  # Max 10 secondes
                    result = self.call('console.read', self.console_id)
                    if result and 'data' in result:
                        output += result['data']
                        
                        # Vérifier si la commande est terminée
                        if not result.get('busy', False):
                            break
                    
                    time.sleep(1)
                
                return {
                    'success': True,
                    'output': output,
                    'command': command
                }
            
        except Exception as e:
            logger.error(f"❌ Erreur exécution commande: {e}")
            return {
                'success': False,
                'error': str(e),
                'command': command
            }
    
    def get_sessions(self):
        """Liste toutes les sessions actives via RPC"""
        try:
            result = self.call('session.list')
            if result:
                sessions = []
                for session_id, session_data in result.items():
                    sessions.append({
                        'session_id': str(session_id),
                        'session_type': session_data.get('type', 'unknown'),
                        'target_ip': session_data.get('session_host', 'unknown'),
                        'target_port': session_data.get('session_port'),
                        'platform': session_data.get('platform', 'unknown'),
                        'via_exploit': session_data.get('via_exploit', 'unknown'),
                        'tunnel_peer': session_data.get('tunnel_peer', 'unknown'),
                        'status': 'active'
                    })
                
                logger.info(f"🎯 {len(sessions)} sessions actives trouvées via RPC")
                return {
                    'success': True,
                    'sessions': sessions
                }
            
            return {
                'success': True,
                'sessions': []
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur récupération sessions: {e}")
            return {
                'success': False,
                'error': str(e),
                'sessions': []
            }
    
    def execute_session_command(self, session_id, command):
        """Exécute une commande sur une session spécifique via RPC"""
        try:
            # Convertir session_id en int si nécessaire
            session_id = int(session_id) if isinstance(session_id, str) else session_id
            
            # Écrire la commande dans la session
            self.call('session.shell_write', session_id, command + '\n')
            
            # Attendre la réponse
            time.sleep(2)
            
            # Lire la réponse
            result = self.call('session.shell_read', session_id)
            
            if result and 'data' in result:
                output = result['data']
            else:
                output = 'Commande exécutée (pas de sortie visible)'
            
            return {
                'success': True,
                'session_id': str(session_id),
                'command': command,
                'output': output
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur commande session {session_id}: {e}")
            return {
                'success': False,
                'session_id': str(session_id),
                'command': command,
                'error': str(e)
            }
    
    def run_exploit(self, exploit_module, options, target, port):
        """Lance un exploit via la console persistante"""
        try:
            commands = [
                f"use {exploit_module}",
                f"set RHOSTS {target}",
                f"set RPORT {port}",
                f"set LHOST 172.20.0.2",  # IP fixe du conteneur
                f"set LPORT 4444"
            ]
            
            # Ajouter les options
            for key, value in options.items():
                if key.upper() not in ['MODE', 'SCAN_TYPE']:  # Exclure les options non-MSF
                    commands.append(f"set {key.upper()} {value}")
            
            commands.extend([
                "exploit -z",  # -z pour arrière-plan
                "sleep 2",     # Attendre un peu
                "sessions -l"   # Lister les sessions
            ])
            
            output = ""
            for cmd in commands:
                result = self.execute_console_command(cmd)
                if result and result.get('success'):
                    cmd_output = result['output']
                    output += f"[CMD] {cmd}\n{cmd_output}\n"
                    logger.info(f"✅ Commande RPC exécutée: {cmd}")
                else:
                    logger.error(f"❌ Échec commande RPC: {cmd}")
            
            # Parser les sessions depuis la sortie
            sessions = self._parse_sessions_from_output(output)
            
            return {
                'success': True,
                'module': exploit_module,
                'target': f"{target}:{port}",
                'raw_output': output,
                'parsed_result': {
                    'sessions_opened': len(sessions),
                    'sessions_detected': sessions,
                    'exploit_attempted': True,
                    'status': 'exploited' if sessions else 'completed'
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur exploitation RPC: {e}")
            return {
                'success': False,
                'error': str(e),
                'module': exploit_module,
                'target': f"{target}:{port}"
            }
    
    def _parse_sessions_from_output(self, output):
        """Parse les sessions depuis la sortie console"""
        sessions = []
        lines = output.split('\n')
        
        for line in lines:
            # Format: "  1  meterpreter x86/linux  192.168.1.10:4444 -> 192.168.1.100:80"
            session_match = re.match(r'\s*(\d+)\s+(\w+)\s+([\w/]+)\s+([\d.:>-\s]+)', line)
            
            if session_match:
                session_id = session_match.group(1)
                session_type = session_match.group(2)
                platform = session_match.group(3)
                connection = session_match.group(4)
                
                # Extraire l'IP cible
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', connection)
                target_ip = ip_match.group(1) if ip_match else 'unknown'
                
                sessions.append({
                    'session_id': session_id,
                    'session_type': session_type,
                    'target_ip': target_ip,
                    'target_port': None,
                    'platform': platform,
                    'detected_at': datetime.now().isoformat()
                })
                
                logger.info(f"🎯 Session RPC détectée: #{session_id} ({session_type}) vers {target_ip}")
            
            # Format alternatif: "Meterpreter session 1 opened"
            elif 'session' in line.lower() and 'opened' in line.lower():
                session_match = re.search(r'(\w+)\s+session\s+(\d+)\s+opened', line, re.IGNORECASE)
                if session_match:
                    session_type = session_match.group(1).lower()
                    session_id = session_match.group(2)
                    
                    # Extraire les IPs
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                    target_ip = ip_match.group(1) if ip_match else 'unknown'
                    target_port = int(ip_match.group(2)) if ip_match else None
                    
                    sessions.append({
                        'session_id': session_id,
                        'session_type': session_type,
                        'target_ip': target_ip,
                        'target_port': target_port,
                        'detected_at': datetime.now().isoformat()
                    })
                    
                    logger.info(f"🎯 Session RPC ouverte: #{session_id} ({session_type}) vers {target_ip}")
        
        return sessions
    
    def test_metasploit_availability(self):
        """Test la disponibilité de Metasploit via RPC"""
        try:
            if not self.authenticated:
                if not self.authenticate():
                    return {
                        'available': False,
                        'error': 'Impossible de s\'authentifier au serveur RPC'
                    }
            
            # Test avec version core
            result = self.call('core.version')
            
            if result and 'version' in result:
                return {
                    'available': True,
                    'version': result['version'],
                    'ruby': result.get('ruby', 'unknown'),
                    'api': result.get('api', 'unknown'),
                    'path': f'RPC Server {self.host}:{self.port}'
                }
            
            return {
                'available': False,
                'error': 'Pas de réponse valide du serveur RPC'
            }
            
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }
    
    def cleanup(self):
        """Nettoie les ressources RPC"""
        try:
            if self.console_id and self.authenticated:
                self.call('console.destroy', self.console_id)
                logger.info(f"🧹 Console RPC {self.console_id} fermée")
            
            if self.authenticated:
                self.call('auth.logout', self.token)
                logger.info("🔐 Déconnexion RPC")
            
            # NE PAS arrêter le processus RPC pour permettre la réutilisation
            # if self._rpc_process:
            #     self._rpc_process.terminate()
            #     logger.info("🛑 Serveur RPC arrêté")
                
        except Exception as e:
            logger.error(f"❌ Erreur nettoyage RPC: {e}")
    
    def __del__(self):
        """Nettoyage automatique"""
        self.cleanup()

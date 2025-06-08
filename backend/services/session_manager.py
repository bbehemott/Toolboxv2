import logging
import time
import psycopg2.extras
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from core.huntkit_tools import HuntKitIntegration

logger = logging.getLogger('toolbox.session_manager')

class SessionManager:
    """Gestionnaire des sessions Metasploit et post-exploitation"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.huntkit = HuntKitIntegration()
    
    def detect_and_register_sessions_from_output(self, output: str, task_id: str, user_id: int) -> List[Dict]:
        """Détecte les sessions dans la sortie et les enregistre - VERSION CORRIGÉE"""
        sessions_detected = self.huntkit.metasploit.parse_sessions_from_output(output)
        registered_sessions = []
        
        for session_data in sessions_detected:
            # ✅ CORRECTION : Utiliser directement le session_id de Metasploit
            metasploit_session_id = session_data['session_id']  # C'est déjà le bon ID MSF
            
            try:
                int(metasploit_session_id)  # Test de validation
            except ValueError:
                logger.error(f"❌ ID session Metasploit invalide: '{metasploit_session_id}'")
                continue
        
            # Vérifier si cette session Metasploit existe déjà
            if self._session_already_exists(metasploit_session_id):
                logger.warning(f"⚠️ Session MSF #{metasploit_session_id} déjà enregistrée - ignorée")
                continue


            db_session_id = self.register_session(
                session_id=metasploit_session_id,  # ✅ ID réel Metasploit
                task_id=task_id,
                target_ip=session_data['target_ip'],
                target_port=session_data.get('target_port'),
                session_type=session_data['session_type'],
                user_id=user_id
            )
            
            if db_session_id:
                registered_sessions.append({
                    'db_id': db_session_id,
                    'metasploit_session_id': metasploit_session_id,  # ✅ Correct ID MSF
                    'target_ip': session_data['target_ip'],
                    'session_type': session_data['session_type']
                })
                
                # Lancer automatiquement la post-exploitation
                self.start_auto_post_exploitation(db_session_id)
        
        return registered_sessions

    def _session_already_exists(self, metasploit_session_id: str) -> bool:
        """Vérifie si une session Metasploit existe déjà en base"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id FROM metasploit_sessions 
                    WHERE session_id = %s AND status = 'active'
                ''', (str(metasploit_session_id),))
            
                return cursor.fetchone() is not None
            
        except Exception as e:
            logger.error(f"❌ Erreur vérification session existante: {e}")
            return False

    def register_session(self, session_id: str, task_id: str, target_ip: str, 
                        target_port: int = None, session_type: str = 'shell',
                        platform: str = None, arch: str = None, user_id: int = None) -> Optional[int]:
        """Enregistre une nouvelle session en base"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO metasploit_sessions 
                    (session_id, task_id, target_ip, target_port, session_type, platform, arch, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                ''', (session_id, task_id, target_ip, target_port, session_type, platform, arch, user_id))
                
                db_session_id = cursor.fetchone()[0]
                conn.commit()
                
                logger.info(f"✅ Session enregistrée: {session_id} -> DB ID {db_session_id}")
                return db_session_id
                
        except Exception as e:
            logger.error(f"❌ Erreur enregistrement session: {e}")
            return None
    
    def start_auto_post_exploitation(self, db_session_id: int) -> bool:
        """Lance le scénario automatique de post-exploitation"""
        try:
            # Récupérer les infos de la session
            session_info = self.get_session_info(db_session_id)
            if not session_info:
                return False
            
            logger.info(f"🚀 Démarrage post-exploitation automatique pour session {session_info['session_id']}")
            
            # Définir les actions automatiques selon le type de session
            actions = self._get_auto_post_exploit_actions(session_info['session_type'])
            
            # Exécuter chaque action
            for action_type, command_func in actions.items():
                self._execute_post_exploit_action(db_session_id, action_type, command_func)
            
            # Marquer la post-exploitation automatique comme terminée
            self._mark_auto_post_exploit_completed(db_session_id)
            
            logger.info(f"✅ Post-exploitation automatique terminée pour session {session_info['session_id']}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur post-exploitation automatique: {e}")
            return False
    
    def _get_auto_post_exploit_actions(self, session_type: str) -> Dict[str, str]:
        """Retourne les actions automatiques selon le type de session"""
        base_actions = {
            'sysinfo': 'sysinfo',
            'users': 'getuid', 
            'processes': 'ps'
        }
        
        if session_type.lower() == 'meterpreter':
            # Actions avancées pour Meterpreter
            base_actions.update({
                'hashdump': 'hashdump',
                'network_scan': 'run post/multi/gather/ping_sweep RHOSTS=192.168.1.0/24'
            })
        
        return base_actions
    
    def _execute_post_exploit_action(self, db_session_id: int, action_type: str, command: str):
        """Exécute une action de post-exploitation - VERSION RPC CORRIGÉE"""
        try:
            # ✅ CORRECTION CRITIQUE : Récupérer le bon session_id Metasploit
            session_info = self.get_session_info(db_session_id)
            if not session_info:
                logger.error(f"❌ Session {db_session_id} non trouvée en base")
                return
        
            # ✅ CORRECTION : Le session_id en base EST l'ID Metasploit réel
            metasploit_session_id = session_info['session_id']
        
            logger.info(f"🔧 Exécution {action_type} sur session MSF #{metasploit_session_id} (DB ID: {db_session_id})")
        
            # Créer l'enregistrement d'action
            action_id = self._create_post_exploit_action(db_session_id, action_type, command)
            if not action_id:
                logger.error(f"❌ Impossible de créer l'action {action_type}")
                return
        
            # Marquer comme en cours
            self._update_post_exploit_action(action_id, 'running')
        
            start_time = time.time()
        
            # ✅ CORRECTION PRINCIPALE : Utiliser le client RPC plutôt que les commandes temporaires
            try:
                # Utiliser le client RPC persistant de HuntKit
                from core.huntkit_tools import HuntKitIntegration
                huntkit = HuntKitIntegration()
            
                msf_session_int = int(metasploit_session_id)
            
                logger.info(f"🎯 Utilisation ID Metasploit: {msf_session_int} (type: {type(msf_session_int)})")

                # Exécuter via RPC persistant
                result = huntkit.metasploit.execute_session_command(
                    msf_session_int, command
                )
            
            except ValueError as ve:
                logger.error(f"❌ ID Metasploit invalide '{metasploit_session_id}': {ve}")
                result = {'success': False, 'error': f'ID session invalide: {metasploit_session_id}'}
            except Exception as rpc_error:
                logger.warning(f"⚠️ RPC échoué pour session {metasploit_session_id}: {rpc_error}")
                result = {'success': False, 'error': str(rpc_error)}
    
            execution_time = int(time.time() - start_time)

            # Mettre à jour avec les résultats
            if result['success']:
                self._update_post_exploit_action(
                    action_id, 'completed', 
                    result_data=result,
                    raw_output=result.get('output'),
                    execution_time=execution_time
                )
                logger.info(f"✅ Action {action_type} terminée (session #{metasploit_session_id})")
            else:
                self._update_post_exploit_action(
                    action_id, 'failed',
                    error_message=result.get('error'),
                    execution_time=execution_time
                )
                logger.error(f"❌ Action {action_type} échouée: {result.get('error')}")
            
        except Exception as e:
            logger.error(f"❌ Erreur exécution action {action_type}: {e}")
            if 'action_id' in locals():
                self._update_post_exploit_action(action_id, 'failed', error_message=str(e))



    def _create_post_exploit_action(self, session_id: int, action_type: str, command: str) -> Optional[int]:
        """Crée un enregistrement d'action de post-exploitation"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO post_exploit_actions 
                    (session_id, action_type, command_executed, status)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                ''', (session_id, action_type, command, 'pending'))
                
                action_id = cursor.fetchone()[0]
                conn.commit()
                return action_id
                
        except Exception as e:
            logger.error(f"❌ Erreur création action: {e}")
            return None
    
    def _update_post_exploit_action(self, action_id: int, status: str, 
                                   result_data: Dict = None, raw_output: str = None,
                                   execution_time: int = None, error_message: str = None):
        """Met à jour une action de post-exploitation"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                updates = ['status = %s']
                params = [status]
                
                if result_data:
                    updates.append('result_data = %s')
                    params.append(json.dumps(result_data))
                
                if raw_output:
                    updates.append('raw_output = %s')
                    params.append(raw_output)
                
                if execution_time is not None:
                    updates.append('execution_time = %s')
                    params.append(execution_time)
                
                if error_message:
                    updates.append('error_message = %s')
                    params.append(error_message)
                
                if status in ['completed', 'failed']:
                    updates.append('completed_at = CURRENT_TIMESTAMP')
                
                query = f"UPDATE post_exploit_actions SET {', '.join(updates)} WHERE id = %s"
                params.append(action_id)
                
                cursor.execute(query, params)
                conn.commit()
                
        except Exception as e:
            logger.error(f"❌ Erreur mise à jour action {action_id}: {e}")
    
    def _mark_auto_post_exploit_completed(self, session_id: int):
        """Marque la post-exploitation automatique comme terminée"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE metasploit_sessions 
                    SET auto_post_exploit_completed = TRUE,
                        manual_takeover_enabled = TRUE,
                        last_interaction = CURRENT_TIMESTAMP
                    WHERE id = %s
                ''', (session_id,))
                conn.commit()
                
        except Exception as e:
            logger.error(f"❌ Erreur marquage completion: {e}")
    
    def get_session_info(self, db_session_id: int) -> Optional[Dict]:
        """Récupère les informations d'une session"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT * FROM metasploit_sessions WHERE id = %s
                ''', (db_session_id,))
                
                row = cursor.fetchone()
                return dict(row) if row else None
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération session {db_session_id}: {e}")
            return None
    
    def get_session_actions(self, db_session_id: int) -> List[Dict]:
        """Récupère toutes les actions d'une session"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT * FROM post_exploit_actions 
                    WHERE session_id = %s 
                    ORDER BY started_at ASC
                ''', (db_session_id,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération actions session {db_session_id}: {e}")
            return []
    
    def get_active_sessions(self, user_id: int = None) -> List[Dict]:
        """Récupère toutes les sessions actives"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                query = '''
                    SELECT s.*, t.task_name, u.username
                    FROM metasploit_sessions s
                    LEFT JOIN tasks t ON s.task_id = t.task_id
                    LEFT JOIN users u ON s.user_id = u.id
                    WHERE s.status = 'active'
                '''
                params = []
                
                if user_id:
                    query += ' AND s.user_id = %s'
                    params.append(user_id)
                
                query += ' ORDER BY s.opened_at DESC'
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération sessions actives: {e}")
            return []

logger.info("🎯 SessionManager chargé pour gestion automatique post-exploitation")

import psycopg2
import psycopg2.extras
import bcrypt
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Union
from contextlib import contextmanager

logger = logging.getLogger('toolbox.database')

class DatabaseManager:
    """Gestionnaire PostgreSQL uniquement - Pas de SQLite"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        logger.info(f"🐘 Connexion PostgreSQL: {database_url.split('@')[1] if '@' in database_url else 'localhost'}")
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour PostgreSQL uniquement"""
        conn = None
        try:
            conn = psycopg2.connect(self.database_url)
            yield conn
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"❌ Erreur PostgreSQL: {e}")
            raise
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"❌ Erreur base de données: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def init_database(self):
        """Initialise les tables PostgreSQL - VERSION AVEC SESSIONS"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Tables existantes (garder le code existant)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id SERIAL PRIMARY KEY,
                    task_id VARCHAR(255) UNIQUE NOT NULL,
                    task_name VARCHAR(100) NOT NULL,
                    task_type VARCHAR(50) NOT NULL,
                    target VARCHAR(255),
                    status VARCHAR(20) DEFAULT 'pending',
                    progress INTEGER DEFAULT 0,
                    user_id INTEGER REFERENCES users(id),
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    result_summary TEXT,
                    error_message TEXT,
                    raw_output TEXT,
                    hidden BOOLEAN DEFAULT FALSE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS module_results (
                    id SERIAL PRIMARY KEY,
                    task_id VARCHAR(255) NOT NULL REFERENCES tasks(task_id),
                    module_name VARCHAR(50) NOT NULL,
                    target VARCHAR(255),
                    scan_type VARCHAR(50),
                    result_data JSONB,
                    raw_output TEXT,
                    scan_duration INTEGER,
                    hosts_discovered INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    severity_high INTEGER DEFAULT 0,
                    severity_medium INTEGER DEFAULT 0,
                    severity_low INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # ✅ NOUVELLES TABLES pour sessions Metasploit
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metasploit_sessions (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(50) NOT NULL,
                    task_id VARCHAR(255) REFERENCES tasks(task_id),
                    target_ip VARCHAR(255) NOT NULL,
                    target_port INTEGER,
                    session_type VARCHAR(50) NOT NULL,
                    platform VARCHAR(100),
                    arch VARCHAR(50),
                    status VARCHAR(20) DEFAULT 'active',
                    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    closed_at TIMESTAMP,
                    last_interaction TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER REFERENCES users(id),
                    auto_post_exploit_completed BOOLEAN DEFAULT FALSE,
                    manual_takeover_enabled BOOLEAN DEFAULT FALSE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS post_exploit_actions (
                    id SERIAL PRIMARY KEY,
                    session_id INTEGER REFERENCES metasploit_sessions(id),
                    action_type VARCHAR(50) NOT NULL,
                    command_executed TEXT,
                    result_data JSONB,
                    raw_output TEXT,
                    status VARCHAR(20) DEFAULT 'pending',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    execution_time INTEGER,
                    error_message TEXT
                )
            ''')
            
            # Index existants (garder)
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_module_results_task_id ON module_results(task_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_module_results_module_name ON module_results(module_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_hidden ON tasks(hidden)')
            
            # ✅ NOUVEAUX Index pour sessions
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_task_id ON metasploit_sessions(task_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_status ON metasploit_sessions(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON metasploit_sessions(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_post_exploit_session ON post_exploit_actions(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_post_exploit_status ON post_exploit_actions(status)')
            
            conn.commit()
            logger.info("✅ Base de données PostgreSQL initialisée avec support sessions")

    # ===== MÉTHODES MANQUANTES AJOUTÉES =====
    
    def get_active_sessions(self, user_id: int = None) -> List[Dict]:
        """Récupère les sessions Metasploit actives"""
        try:
            with self.get_connection() as conn:
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
                sessions = [dict(row) for row in cursor.fetchall()]
                
                logger.debug(f"🎯 {len(sessions)} sessions actives récupérées")
                return sessions
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération sessions actives: {e}")
            return []

    def get_session_by_id(self, session_id: int) -> Optional[Dict]:
        """Récupère une session par son ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT s.*, t.task_name, u.username
                    FROM metasploit_sessions s
                    LEFT JOIN tasks t ON s.task_id = t.task_id
                    LEFT JOIN users u ON s.user_id = u.id
                    WHERE s.id = %s
                ''', (session_id,))
                
                row = cursor.fetchone()
                if row:
                    logger.debug(f"🎯 Session trouvée: {session_id}")
                    return dict(row)
                else:
                    logger.warning(f"⚠️ Session non trouvée: {session_id}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ Erreur récupération session {session_id}: {e}")
            return None

    def create_session(self, session_id: str, task_id: str, target_ip: str, 
                      target_port: int = None, session_type: str = 'shell',
                      platform: str = None, arch: str = None, user_id: int = None) -> Optional[int]:
        """Crée une nouvelle session Metasploit"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO metasploit_sessions 
                    (session_id, task_id, target_ip, target_port, session_type, platform, arch, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                ''', (session_id, task_id, target_ip, target_port, session_type, platform, arch, user_id))
                
                db_session_id = cursor.fetchone()[0]
                conn.commit()
                
                logger.info(f"✅ Session créée: {session_id} -> DB ID {db_session_id}")
                return db_session_id
                
        except Exception as e:
            logger.error(f"❌ Erreur création session: {e}")
            return None

    def update_session_status(self, session_id: int, status: str, 
                             auto_post_exploit_completed: bool = None,
                             manual_takeover_enabled: bool = None):
        """Met à jour le statut d'une session"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                updates = ['status = %s', 'last_interaction = CURRENT_TIMESTAMP']
                params = [status]
                
                if auto_post_exploit_completed is not None:
                    updates.append('auto_post_exploit_completed = %s')
                    params.append(auto_post_exploit_completed)
                
                if manual_takeover_enabled is not None:
                    updates.append('manual_takeover_enabled = %s')
                    params.append(manual_takeover_enabled)
                
                if status == 'closed':
                    updates.append('closed_at = CURRENT_TIMESTAMP')
                
                query = f"UPDATE metasploit_sessions SET {', '.join(updates)} WHERE id = %s"
                params.append(session_id)
                
                cursor.execute(query, params)
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.debug(f"🎯 Session {session_id} mise à jour: {status}")
                else:
                    logger.warning(f"⚠️ Session {session_id} non trouvée pour mise à jour")
                    
        except Exception as e:
            logger.error(f"❌ Erreur mise à jour session {session_id}: {e}")

    def create_post_exploit_action(self, session_id: int, action_type: str, 
                                  command: str, user_id: int = None) -> Optional[int]:
        """Crée une action de post-exploitation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO post_exploit_actions 
                    (session_id, action_type, command_executed, status)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                ''', (session_id, action_type, command, 'pending'))
                
                action_id = cursor.fetchone()[0]
                conn.commit()
                
                logger.debug(f"📋 Action créée: {action_type} -> ID {action_id}")
                return action_id
                
        except Exception as e:
            logger.error(f"❌ Erreur création action: {e}")
            return None

    def update_post_exploit_action(self, action_id: int, status: str,
                                  result_data: Dict = None, raw_output: str = None,
                                  execution_time: int = None, error_message: str = None):
        """Met à jour une action de post-exploitation"""
        try:
            with self.get_connection() as conn:
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
                
                logger.debug(f"📋 Action {action_id} mise à jour: {status}")
                
        except Exception as e:
            logger.error(f"❌ Erreur mise à jour action {action_id}: {e}")

    def get_session_actions(self, session_id: int) -> List[Dict]:
        """Récupère toutes les actions d'une session"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT * FROM post_exploit_actions 
                    WHERE session_id = %s 
                    ORDER BY started_at ASC
                ''', (session_id,))
                
                actions = [dict(row) for row in cursor.fetchall()]
                logger.debug(f"📋 {len(actions)} actions récupérées pour session {session_id}")
                return actions
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération actions session {session_id}: {e}")
            return []

    def get_sessions_statistics(self) -> Dict:
        """Récupère les statistiques des sessions"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                stats = {}
                
                # Statistiques sessions
                cursor.execute('''
                    SELECT status, COUNT(*) as count
                    FROM metasploit_sessions
                    GROUP BY status
                ''')
                session_stats = {row['status']: row['count'] for row in cursor.fetchall()}
                stats['sessions'] = session_stats
                
                # Statistiques post-exploitation
                cursor.execute('''
                    SELECT action_type, status, COUNT(*) as count
                    FROM post_exploit_actions
                    GROUP BY action_type, status
                ''')
                action_stats = {}
                for row in cursor.fetchall():
                    action_type = row['action_type']
                    if action_type not in action_stats:
                        action_stats[action_type] = {}
                    action_stats[action_type][row['status']] = row['count']
                stats['post_exploit_actions'] = action_stats
                
                # Sessions par utilisateur
                cursor.execute('''
                    SELECT u.username, COUNT(s.id) as session_count
                    FROM metasploit_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.status = 'active'
                    GROUP BY u.username
                    ORDER BY session_count DESC
                ''')
                user_stats = {row['username']: row['session_count'] for row in cursor.fetchall()}
                stats['sessions_by_user'] = user_stats
                
                logger.debug(f"📊 Statistiques sessions récupérées")
                return stats
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération statistiques sessions: {e}")
            return {}

    def cleanup_old_sessions(self, days: int = 7) -> int:
        """Nettoie les anciennes sessions fermées"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Supprimer d'abord les actions associées
                cursor.execute('''
                    DELETE FROM post_exploit_actions 
                    WHERE session_id IN (
                        SELECT id FROM metasploit_sessions 
                        WHERE status = 'closed' 
                        AND closed_at < CURRENT_TIMESTAMP - INTERVAL '%s days'
                    )
                ''', (days,))
                actions_deleted = cursor.rowcount
                
                # Puis supprimer les sessions
                cursor.execute('''
                    DELETE FROM metasploit_sessions 
                    WHERE status = 'closed' 
                    AND closed_at < CURRENT_TIMESTAMP - INTERVAL '%s days'
                ''', (days,))
                sessions_deleted = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"🧹 Sessions nettoyées: {sessions_deleted} sessions + {actions_deleted} actions (>{days} jours)")
                return sessions_deleted
                
        except Exception as e:
            logger.error(f"❌ Erreur nettoyage sessions: {e}")
            return 0


    def hide_task(self, task_id: str) -> bool:
        """Masque une tâche de l'historique"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE tasks SET hidden = TRUE WHERE task_id = %s
                ''', (task_id,))
                conn.commit()
                affected_rows = cursor.rowcount
                logger.info(f"🙈 Tâche {task_id} masquée ({affected_rows} lignes)")
                return affected_rows > 0
        except Exception as e:
            logger.error(f"❌ Erreur masquage tâche {task_id}: {e}")
            return False
    
    def cleanup_old_tasks(self, days: int = 30) -> int:
        """Nettoie les anciennes tâches (marque comme hidden)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE tasks SET hidden = TRUE
                    WHERE completed_at < CURRENT_TIMESTAMP - INTERVAL '%s days'
                    AND status IN ('completed', 'failed', 'cancelled')
                    AND hidden = FALSE
                ''', (days,))
                conn.commit()
                cleaned_count = cursor.rowcount
                logger.info(f"🧹 {cleaned_count} tâches anciennes masquées (>{days} jours)")
                return cleaned_count
        except Exception as e:
            logger.error(f"❌ Erreur nettoyage: {e}")
            return 0
    
    def cleanup_all_completed_tasks(self) -> int:
        """Supprime DÉFINITIVEMENT toutes les tâches terminées"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                # Supprimer d'abord les résultats de modules
                cursor.execute('''
                    DELETE FROM module_results 
                    WHERE task_id IN (
                        SELECT task_id FROM tasks 
                        WHERE status IN ('completed', 'failed', 'cancelled')
                    )
                ''')
                modules_deleted = cursor.rowcount
                
                # Puis supprimer les tâches
                cursor.execute('''
                    DELETE FROM tasks 
                    WHERE status IN ('completed', 'failed', 'cancelled')
                ''')
                tasks_deleted = cursor.rowcount
                
                conn.commit()
                logger.info(f"🗑️ Purge complète: {tasks_deleted} tâches + {modules_deleted} résultats supprimés")
                return tasks_deleted
        except Exception as e:
            logger.error(f"❌ Erreur purge complète: {e}")
            return 0
    
    # ===== AUTRES MÉTHODES (inchangées mais optimisées PostgreSQL) =====
    
    def create_user(self, username: str, password: str, role: str = 'viewer') -> Optional[int]:
        """Crée un nouvel utilisateur"""
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, role)
                    VALUES (%s, %s, %s) RETURNING id
                ''', (username, password_hash.decode('utf-8'), role))
                user_id = cursor.fetchone()[0]
                conn.commit()
                logger.info(f"👤 Utilisateur créé: {username} ({role}) - ID: {user_id}")
                return user_id
        except psycopg2.IntegrityError:
            logger.warning(f"⚠️ Utilisateur {username} existe déjà")
            return None
        except Exception as e:
            logger.error(f"❌ Erreur création utilisateur {username}: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authentifie un utilisateur"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT id, username, password_hash, role, active
                    FROM users WHERE username = %s AND active = TRUE
                ''', (username,))
                
                user = cursor.fetchone()
                if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                    # Mettre à jour last_login
                    cursor.execute('''
                        UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s
                    ''', (user['id'],))
                    conn.commit()
                    
                    logger.info(f"🔐 Connexion réussie: {username}")
                    return {
                        'id': user['id'],
                        'username': user['username'],
                        'role': user['role']
                    }
                else:
                    logger.warning(f"🚫 Échec connexion: {username}")
                    return None
        except Exception as e:
            logger.error(f"❌ Erreur authentification {username}: {e}")
            return None
    
    def get_users(self) -> List[Dict]:
        """Récupère tous les utilisateurs"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT id, username, role, created_at, last_login, active
                    FROM users ORDER BY username
                ''')
                users = [dict(row) for row in cursor.fetchall()]
                logger.debug(f"👥 {len(users)} utilisateurs récupérés")
                return users
        except Exception as e:
            logger.error(f"❌ Erreur récupération utilisateurs: {e}")
            return []
    
    def create_task(self, task_id: str, task_name: str, task_type: str, 
                   target: str = None, user_id: int = None) -> int:
        """Crée une nouvelle tâche"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO tasks (task_id, task_name, task_type, target, user_id)
                    VALUES (%s, %s, %s, %s, %s) RETURNING id
                ''', (task_id, task_name, task_type, target, user_id))
                task_db_id = cursor.fetchone()[0]
                conn.commit()
                logger.info(f"📋 Tâche créée: {task_name} ({task_type}) - ID: {task_db_id}")
                return task_db_id
        except Exception as e:
            logger.error(f"❌ Erreur création tâche {task_name}: {e}")
            raise
    
    def update_task_status(self, task_id: str, status: str, progress: int = None,
                          result_summary: str = None, error_message: str = None):
        """Met à jour le statut d'une tâche"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                updates = ['status = %s']
                params = [status]
                
                if progress is not None:
                    updates.append('progress = %s')
                    params.append(progress)
                
                if result_summary:
                    updates.append('result_summary = %s')
                    params.append(result_summary)
                
                if error_message:
                    updates.append('error_message = %s')
                    params.append(error_message)
                
                if status in ['completed', 'failed', 'cancelled']:
                    updates.append('completed_at = CURRENT_TIMESTAMP')
                
                query = f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = %s"
                params.append(task_id)
                
                cursor.execute(query, params)
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.debug(f"📊 Tâche {task_id} mise à jour: {status}")
                else:
                    logger.warning(f"⚠️ Tâche {task_id} non trouvée pour mise à jour")
        except Exception as e:
            logger.error(f"❌ Erreur mise à jour tâche {task_id}: {e}")
            
    def get_tasks(self, user_id: int = None, include_hidden: bool = False, 
                  limit: int = 50) -> List[Dict]:
        """Récupère les tâches avec filtres PostgreSQL optimisés"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                conditions = []
                params = []
                
                if not include_hidden:
                    conditions.append('t.hidden = FALSE')
                
                if user_id:
                    conditions.append('t.user_id = %s')
                    params.append(user_id)
                
                where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
                
                cursor.execute(f'''
                    SELECT t.*, u.username
                    FROM tasks t
                    LEFT JOIN users u ON t.user_id = u.id
                    {where_clause}
                    ORDER BY t.started_at DESC
                    LIMIT %s
                ''', params + [limit])
                
                tasks = [dict(row) for row in cursor.fetchall()]
                logger.debug(f"📋 {len(tasks)} tâches récupérées")
                return tasks
        except Exception as e:
            logger.error(f"❌ Erreur récupération tâches: {e}")
            return []
    
    def get_task_by_id(self, task_id: str) -> Optional[Dict]:
        """Récupère une tâche par son ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT t.*, u.username
                    FROM tasks t
                    LEFT JOIN users u ON t.user_id = u.id
                    WHERE t.task_id = %s
                ''', (task_id,))
                
                row = cursor.fetchone()
                if row:
                    logger.debug(f"📋 Tâche trouvée: {task_id}")
                    return dict(row)
                else:
                    logger.warning(f"⚠️ Tâche non trouvée: {task_id}")
                    return None
        except Exception as e:
            logger.error(f"❌ Erreur récupération tâche {task_id}: {e}")
            return None
    
    def save_module_result(self, task_id: str, module_name: str, target: str,
                          scan_type: str, result_data: Dict, raw_output: str = None,
                          scan_duration: int = None, stats: Dict = None) -> int:
        """Sauvegarde un résultat de module avec JSONB PostgreSQL"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Extraire les statistiques
                hosts_discovered = 0
                vulnerabilities_found = 0
                severity_high = 0
                severity_medium = 0
                severity_low = 0
                
                if stats:
                    hosts_discovered = stats.get('hosts_discovered', 0)
                    vulnerabilities_found = stats.get('vulnerabilities_found', 0)
                    severity_high = stats.get('severity_high', 0)
                    severity_medium = stats.get('severity_medium', 0)
                    severity_low = stats.get('severity_low', 0)
                
                cursor.execute('''
                    INSERT INTO module_results (
                        task_id, module_name, target, scan_type, result_data, raw_output,
                        scan_duration, hosts_discovered, vulnerabilities_found,
                        severity_high, severity_medium, severity_low
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                ''', (
                    task_id, module_name, target, scan_type, 
                    json.dumps(result_data), raw_output, scan_duration,
                    hosts_discovered, vulnerabilities_found,
                    severity_high, severity_medium, severity_low
                ))
                
                result_id = cursor.fetchone()[0]
                conn.commit()
                logger.info(f"💾 Résultat sauvegardé: {module_name} (ID: {result_id})")
                return result_id
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde résultat {module_name}: {e}")
            raise
    
    def get_module_results(self, task_id: str = None, module_name: str = None,
                          limit: int = 100) -> List[Dict]:
        """Récupère les résultats de modules avec JSONB"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                conditions = []
                params = []
                
                if task_id:
                    conditions.append('task_id = %s')
                    params.append(task_id)
                
                if module_name:
                    conditions.append('module_name = %s')
                    params.append(module_name)
                
                where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
                
                cursor.execute(f'''
                    SELECT * FROM module_results
                    {where_clause}
                    ORDER BY created_at DESC
                    LIMIT %s
                ''', params + [limit])
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Pas besoin de parser JSON avec JSONB PostgreSQL
                    results.append(result)
                
                logger.debug(f"📊 {len(results)} résultats de modules récupérés")
                return results
        except Exception as e:
            logger.error(f"❌ Erreur récupération résultats: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Récupère des statistiques avec requêtes PostgreSQL optimisées"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                stats = {}
                
                # Statistiques tâches
                cursor.execute('''
                    SELECT status, COUNT(*) as count
                    FROM tasks
                    WHERE hidden = FALSE
                    GROUP BY status
                ''')
                task_stats = {row['status']: row['count'] for row in cursor.fetchall()}
                stats['tasks'] = task_stats
                
                # Utilisateurs actifs
                cursor.execute('SELECT COUNT(*) as count FROM users WHERE active = TRUE')
                stats['active_users'] = cursor.fetchone()['count']
                
                # Statistiques modules avec agrégations PostgreSQL
                cursor.execute('''
                    SELECT 
                        module_name,
                        COUNT(*) as total_scans,
                        SUM(hosts_discovered) as total_hosts,
                        SUM(vulnerabilities_found) as total_vulns,
                        SUM(severity_high) as total_high,
                        SUM(severity_medium) as total_medium,
                        SUM(severity_low) as total_low
                    FROM module_results
                    GROUP BY module_name
                ''')
                module_stats = {row['module_name']: dict(row) for row in cursor.fetchall()}
                stats['modules'] = module_stats
                
                logger.debug(f"📊 Statistiques récupérées: {len(stats)} catégories")
                return stats
        except Exception as e:
            logger.error(f"❌ Erreur récupération statistiques: {e}")
            return {}
    
    def create_default_admin(self):
        """Crée un utilisateur admin par défaut si aucun n'existe"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Vérifier si des utilisateurs existent
                cursor.execute('SELECT COUNT(*) FROM users')
                user_count = cursor.fetchone()[0]
                
                if user_count == 0:
                    # Créer admin par défaut
                    password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute('''
                        INSERT INTO users (username, password_hash, role)
                        VALUES (%s, %s, %s)
                    ''', ('admin', password_hash.decode('utf-8'), 'admin'))
                    conn.commit()
                    logger.info("👤 Utilisateur admin par défaut créé (admin/admin123)")
                else:
                    logger.debug(f"👥 {user_count} utilisateurs déjà présents")
        except Exception as e:
            logger.error(f"❌ Erreur création admin par défaut: {e}")

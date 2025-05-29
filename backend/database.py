import sqlite3
import bcrypt
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from contextlib import contextmanager

logger = logging.getLogger('toolbox.database')

class DatabaseManager:
    """Gestionnaire unifié pour toute la base de données"""
    
    def __init__(self, db_path: Union[str, Path]):
        self.db_path = str(db_path)
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions SQLite"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Retourner des dict
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Erreur base de données: {e}")
            raise
        finally:
            conn.close()
    
    def init_database(self):
        """Initialise toutes les tables nécessaires"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table utilisateurs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Table tâches (Celery + autres)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT UNIQUE NOT NULL,
                    task_name TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    target TEXT,
                    status TEXT DEFAULT 'pending',
                    progress INTEGER DEFAULT 0,
                    user_id INTEGER,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    result_summary TEXT,
                    error_message TEXT,
                    raw_output TEXT,
                    hidden BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Table scans OpenVAS
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_name TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    openvas_task_id TEXT,
                    openvas_target_id TEXT,
                    openvas_config_id TEXT,
                    status TEXT DEFAULT 'created',
                    progress INTEGER DEFAULT 0,
                    user_id INTEGER,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    result_summary TEXT,
                    estimated_duration TEXT,
                    hidden BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Table résultats de modules
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS module_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    target TEXT,
                    result_data TEXT,  -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (task_id) REFERENCES tasks (task_id)
                )
            ''')
            
            conn.commit()
            logger.info("Base de données initialisée")
    
    def create_default_admin(self):
        """Crée un utilisateur admin par défaut si aucun n'existe"""
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
                    VALUES (?, ?, ?)
                ''', ('admin', password_hash, 'admin'))
                conn.commit()
                logger.info("Utilisateur admin par défaut créé (admin/admin123)")
    
    # ===== MÉTHODES UTILISATEURS =====
    
    def create_user(self, username: str, password: str, role: str = 'viewer') -> Optional[int]:
        """Crée un nouvel utilisateur"""
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                ''', (username, password_hash, role))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            logger.warning(f"Utilisateur {username} existe déjà")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authentifie un utilisateur"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, password_hash, role, active
                FROM users WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            if user and user['active'] and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
                # Mettre à jour last_login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
                ''', (user['id'],))
                conn.commit()
                
                return {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role']
                }
        return None
    
    def get_users(self) -> List[Dict]:
        """Récupère tous les utilisateurs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, role, created_at, last_login, active
                FROM users ORDER BY username
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    # ===== MÉTHODES TÂCHES =====
    
    def create_task(self, task_id: str, task_name: str, task_type: str, 
                   target: str = None, user_id: int = None) -> int:
        """Crée une nouvelle tâche"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tasks (task_id, task_name, task_type, target, user_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (task_id, task_name, task_type, target, user_id))
            conn.commit()
            return cursor.lastrowid
    
    def update_task_status(self, task_id: str, status: str, progress: int = None,
                          result_summary: str = None, error_message: str = None):
        """Met à jour le statut d'une tâche"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            updates = ['status = ?']
            params = [status]
            
            if progress is not None:
                updates.append('progress = ?')
                params.append(progress)
            
            if result_summary:
                updates.append('result_summary = ?')
                params.append(result_summary)
            
            if error_message:
                updates.append('error_message = ?')
                params.append(error_message)
            
            if status in ['completed', 'failed']:
                updates.append('completed_at = CURRENT_TIMESTAMP')
            
            query = f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = ?"
            params.append(task_id)
            
            cursor.execute(query, params)
            conn.commit()
    
    def get_tasks(self, user_id: int = None, include_hidden: bool = False, 
                  limit: int = 50) -> List[Dict]:
        """Récupère les tâches"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if not include_hidden:
                conditions.append('hidden = 0')
            
            if user_id:
                conditions.append('user_id = ?')
                params.append(user_id)
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            cursor.execute(f'''
                SELECT t.*, u.username
                FROM tasks t
                LEFT JOIN users u ON t.user_id = u.id
                {where_clause}
                ORDER BY t.started_at DESC
                LIMIT ?
            ''', params + [limit])
            
            return [dict(row) for row in cursor.fetchall()]
    
    def hide_task(self, task_id: str) -> bool:
        """Masque une tâche"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE tasks SET hidden = 1 WHERE task_id = ?', (task_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    # ===== MÉTHODES SCANS OPENVAS =====
    
    def create_scan(self, scan_name: str, target_ip: str, scan_type: str,
                   openvas_task_id: str = None, user_id: int = None) -> int:
        """Crée un nouveau scan OpenVAS"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (scan_name, target_ip, scan_type, openvas_task_id, user_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_name, target_ip, scan_type, openvas_task_id, user_id))
            conn.commit()
            return cursor.lastrowid
    
    def get_scans(self, user_id: int = None, include_hidden: bool = False,
                  active_only: bool = False, limit: int = 50) -> List[Dict]:
        """Récupère les scans"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if not include_hidden:
                conditions.append('hidden = 0')
            
            if active_only:
                conditions.append("status NOT IN ('completed', 'failed', 'stopped')")
            
            if user_id:
                conditions.append('user_id = ?')
                params.append(user_id)
            
            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            
            cursor.execute(f'''
                SELECT s.*, u.username
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.id
                {where_clause}
                ORDER BY s.started_at DESC
                LIMIT ?
            ''', params + [limit])
            
            return [dict(row) for row in cursor.fetchall()]
    
    # ===== MÉTHODES UTILITAIRES =====
    
    def get_stats(self) -> Dict:
        """Récupère des statistiques générales"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Statistiques tâches
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM tasks
                WHERE hidden = 0
                GROUP BY status
            ''')
            task_stats = {row['status']: row['count'] for row in cursor.fetchall()}
            stats['tasks'] = task_stats
            
            # Statistiques scans
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM scans
                WHERE hidden = 0
                GROUP BY status
            ''')
            scan_stats = {row['status']: row['count'] for row in cursor.fetchall()}
            stats['scans'] = scan_stats
            
            # Utilisateurs actifs
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE active = 1')
            stats['active_users'] = cursor.fetchone()['count']
            
            return stats
    
    def cleanup_old_tasks(self, days: int = 30) -> int:
        """Nettoie les anciennes tâches"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE tasks SET hidden = 1
                WHERE completed_at < datetime('now', '-{} days')
                AND status IN ('completed', 'failed')
            '''.format(days))
            conn.commit()
            return cursor.rowcount

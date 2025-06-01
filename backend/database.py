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
    """Gestionnaire unifié pour PostgreSQL"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions PostgreSQL"""
        conn = None
        try:
            conn = psycopg2.connect(self.database_url)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Erreur base de données: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def init_database(self):
        """Initialise toutes les tables nécessaires"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table utilisateurs
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
            
            # Table tâches (Celery + autres)
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
            
            # Table résultats de modules - VERSION ENRICHIE
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS module_results (
                    id SERIAL PRIMARY KEY,
                    task_id VARCHAR(255) NOT NULL REFERENCES tasks(task_id),
                    module_name VARCHAR(50) NOT NULL,
                    target VARCHAR(255),
                    scan_type VARCHAR(50),
                    result_data JSONB,  -- JSON avec index
                    raw_output TEXT,
                    scan_duration INTEGER, -- en secondes
                    hosts_discovered INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    severity_high INTEGER DEFAULT 0,
                    severity_medium INTEGER DEFAULT 0,
                    severity_low INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Index pour les performances
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_module_results_task_id 
                ON module_results(task_id)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_module_results_module_name 
                ON module_results(module_name)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_tasks_status 
                ON tasks(status)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_tasks_user_id 
                ON tasks(user_id)
            ''')
            
            conn.commit()
            logger.info("✅ Base de données PostgreSQL initialisée")
    
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
                    VALUES (%s, %s, %s)
                ''', ('admin', password_hash.decode('utf-8'), 'admin'))
                conn.commit()
                logger.info("👤 Utilisateur admin par défaut créé (admin/admin123)")
    
    # ===== MÉTHODES UTILISATEURS =====
    
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
                return user_id
        except psycopg2.IntegrityError:
            logger.warning(f"⚠️ Utilisateur {username} existe déjà")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authentifie un utilisateur"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT id, username, password_hash, role, active
                FROM users WHERE username = %s
            ''', (username,))
            
            user = cursor.fetchone()
            if user and user['active'] and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Mettre à jour last_login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s
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
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
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
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            ''', (task_id, task_name, task_type, target, user_id))
            task_db_id = cursor.fetchone()[0]
            conn.commit()
            return task_db_id
    
    def update_task_status(self, task_id: str, status: str, progress: int = None,
                          result_summary: str = None, error_message: str = None):
        """Met à jour le statut d'une tâche"""
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
            
            if status in ['completed', 'failed']:
                updates.append('completed_at = CURRENT_TIMESTAMP')
            
            query = f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = %s"
            params.append(task_id)
            
            cursor.execute(query, params)
            conn.commit()
    
    def get_tasks(self, user_id: int = None, include_hidden: bool = False, 
                  limit: int = 50) -> List[Dict]:
        """Récupère les tâches"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            conditions = []
            params = []
            
            if not include_hidden:
                conditions.append('hidden = FALSE')
            
            if user_id:
                conditions.append('user_id = %s')
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
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_task_by_id(self, task_id: str) -> Optional[Dict]:
        """Récupère une tâche par son ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT t.*, u.username
                FROM tasks t
                LEFT JOIN users u ON t.user_id = u.id
                WHERE t.task_id = %s
            ''', (task_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # ===== MÉTHODES RÉSULTATS DE MODULES =====
    
    def save_module_result(self, task_id: str, module_name: str, target: str,
                          scan_type: str, result_data: Dict, raw_output: str = None,
                          scan_duration: int = None, stats: Dict = None) -> int:
        """Sauvegarde un résultat de module avec statistiques"""
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
            return result_id
    
    def get_module_results(self, task_id: str = None, module_name: str = None,
                          limit: int = 100) -> List[Dict]:
        """Récupère les résultats de modules"""
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
                # Parse JSON data
                if result['result_data']:
                    result['result_data'] = json.loads(result['result_data'])
                results.append(result)
            
            return results
    
    # ===== MÉTHODES UTILITAIRES =====
    
    def get_stats(self) -> Dict:
        """Récupère des statistiques générales"""
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
            
            # Statistiques modules
            cursor.execute('''
                SELECT 
                    module_name,
                    COUNT(*) as total_scans,
                    SUM(hosts_discovered) as total_hosts,
                    SUM(vulnerabilities_found) as total_vulns
                FROM module_results
                GROUP BY module_name
            ''')
            module_stats = {row['module_name']: dict(row) for row in cursor.fetchall()}
            stats['modules'] = module_stats
            
            return stats
    
    def cleanup_old_tasks(self, days: int = 30) -> int:
        """Nettoie les anciennes tâches"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE tasks SET hidden = TRUE
                WHERE completed_at < CURRENT_TIMESTAMP - INTERVAL '%s days'
                AND status IN ('completed', 'failed', 'cancelled')
                AND hidden = FALSE
            ''', (days,))
            conn.commit()
            return cursor.rowcount

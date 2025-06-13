import psycopg2
import psycopg2.extras
import bcrypt
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Union
from contextlib import contextmanager
from security import MinIOClient, KeyManagementService, EncryptionService

logger = logging.getLogger('toolbox.database')

class DatabaseManager:
    """Gestionnaire PostgreSQL uniquement - Pas de SQLite"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        logger.info(f"🐘 Connexion PostgreSQL: {database_url.split('@')[1] if '@' in database_url else 'localhost'}")
        self.init_database()
        try:
            self.minio_client = MinIOClient()
            if self.minio_client.is_available():
                self.key_manager = KeyManagementService(self.minio_client.get_client())
                self.crypto_service = EncryptionService(self.key_manager)
                logger.info("🔐 Services de sécurité MinIO initialisés")
            else:
                logger.warning("⚠️ MinIO non disponible - chiffrement désactivé")
                self.crypto_service = None
                self.key_manager = None
        except Exception as e:
            logger.error(f"❌ Erreur init sécurité MinIO: {e}")
            self.crypto_service = None
            self.key_manager = None

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
        """Initialise les tables PostgreSQL"""
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
            
            # Table tâches
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
            
            # Table résultats de modules
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
            
            # Index pour performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_module_results_task_id ON module_results(task_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_module_results_module_name ON module_results(module_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_hidden ON tasks(hidden)')
            
            conn.commit()
            logger.info("✅ Base de données PostgreSQL initialisée")
    
    # ===== MÉTHODES MANQUANTES AJOUTÉES =====
    
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
                          result_summary: str = None, error_message: str = None, raw_output: str = None):
        """Met à jour le statut d'une tâche avec chiffrement automatique"""
        try:
            # ===== NOUVEAU: Chiffrer raw_output automatiquement =====
            if raw_output and self.crypto_service:
                raw_output = self.crypto_service.encrypt_sensitive_data(raw_output, "raw_output")
            # ===== NOUVEAU: Chiffrer error_message si sensible =====
            if error_message and len(error_message) > 100 and self.crypto_service:
                error_message = self.crypto_service.encrypt_sensitive_data(error_message, "error_message")


            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                update_fields = ['status = %s', 'updated_at = CURRENT_TIMESTAMP']
                values = [status]
                
                if progress is not None:
                    update_fields.append('progress = %s')
                    values.append(progress)
                
                if result_summary:
                    update_fields.append('result_summary = %s')
                    values.append(result_summary)
                
                if error_message:
                    update_fields.append('error_message = %s')
                    values.append(error_message)
                
                if raw_output:
                    update_fields.append('raw_output = %s')
                    values.append(raw_output)
                
                # Compléter la requête
                if status == 'completed':
                    update_fields.append('completed_at = CURRENT_TIMESTAMP')
                
                values.append(task_id)
                
                cursor.execute(f'''
                    UPDATE tasks SET {', '.join(update_fields)}
                    WHERE task_id = %s
                ''', values)
                
                conn.commit()
                logger.debug(f"📋 Tâche mise à jour: {task_id} → {status}")
                
        except Exception as e:
            logger.error(f"❌ Erreur mise à jour tâche {task_id}: {e}")
            raise
    

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

    def _encrypt_if_needed(self, data: str, data_type: str = "general") -> str:
        """Chiffre si le service est disponible"""
        if self.crypto_service and data and len(data) > 0:
            return self.crypto_service.encrypt_sensitive_data(data, data_type)
        return data
    
    def _decrypt_if_needed(self, encrypted_data: str, data_type: str = "general") -> str:
        """Déchiffre si nécessaire"""
        if self.crypto_service and encrypted_data:
            return self.crypto_service.decrypt_sensitive_data(encrypted_data, data_type)
        return encrypted_data
    
    def get_security_status(self) -> Dict:
        """Statut des services de sécurité"""
        return {
            'minio': self.minio_client.get_status() if self.minio_client else {'available': False},
            'encryption': self.crypto_service.get_encryption_status() if self.crypto_service else {'available': False},
            'key_management': self.key_manager.get_status() if self.key_manager else {'available': False}
        }


    def test_encryption(self) -> bool:
        """Teste le système de chiffrement"""
        if not self.crypto_service:
            logger.info("ℹ️ Service de chiffrement non disponible")
            return False
        
        return self.crypto_service.test_encryption_cycle()

    def get_task_details(self, task_id: str) -> Optional[Dict]:
        """Récupère les détails d'une tâche avec déchiffrement automatique"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute('''
                    SELECT * FROM tasks WHERE task_id = %s
                ''', (task_id,))
                
                task = cursor.fetchone()
                if task:
                    task_dict = dict(task)
                    
                    # Déchiffrer les données sensibles si service disponible
                    if hasattr(self, 'crypto_service') and self.crypto_service:
                        if task_dict.get('raw_output'):
                            task_dict['raw_output'] = self.crypto_service.decrypt_sensitive_data(
                                task_dict['raw_output'], "raw_output"
                            )
                        
                        if task_dict.get('error_message') and len(task_dict['error_message']) > 100:
                            task_dict['error_message'] = self.crypto_service.decrypt_sensitive_data(
                                task_dict['error_message'], "error_message"
                            )
                    
                    return task_dict
                return None
                
        except Exception as e:
            logger.error(f"❌ Erreur récupération tâche {task_id}: {e}")
            return None



    def save_traffic_result(self, task_id, user_id, task_type, target, result_data, pcap_file=None):
        """Sauver résultat d'analyse traffic en BDD"""
        
        query = """
        INSERT INTO traffic_results (
            task_id, user_id, task_type, target, result_data, 
            pcap_file, created_at
        ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (
                        task_id, user_id, task_type, target,
                        json.dumps(result_data), pcap_file
                    ))
                    conn.commit()
                    logger.info(f"✅ Résultat traffic sauvé: {task_id}")
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde traffic: {e}")
            raise
    
    def get_user_traffic_results(self, user_id, limit=10):
        """Récupérer résultats traffic d'un utilisateur"""
        
        query = """
        SELECT task_id, task_type, target, result_data, pcap_file, created_at
        FROM traffic_results 
        WHERE user_id = %s 
        ORDER BY created_at DESC 
        LIMIT %s
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (user_id, limit))
                    results = cursor.fetchall()
                    
                    return [{
                        'task_id': row[0],
                        'task_type': row[1], 
                        'target': row[2],
                        'result_data': json.loads(row[3]) if row[3] else {},
                        'pcap_file': row[4],
                        'created_at': row[5]
                    } for row in results]
                    
        except Exception as e:
            logger.error(f"❌ Erreur récupération results: {e}")
            return []

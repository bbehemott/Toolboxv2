import sqlite3
import bcrypt
import logging
import json
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

    def get_task_by_id(self, task_id: str) -> Optional[Dict]:
        """Récupère une tâche par son ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT t.*, u.username
                FROM tasks t
                LEFT JOIN users u ON t.user_id = u.id
                WHERE t.task_id = ?
            ''', (task_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # ===== MÉTHODES MODULES PENTEST =====
    
    def save_module_result(self, task_id: str, module_name: str, result_data: dict):
        """Sauvegarde les résultats détaillés d'un module"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO module_results (task_id, module_name, target, result_data)
                    VALUES (?, ?, ?, ?)
                ''', (
                    task_id,
                    module_name,
                    result_data.get('target', ''),
                    json.dumps(result_data)
                ))
                conn.commit()
                logger.info(f"✅ Résultats sauvegardés: {module_name} pour tâche {task_id}")
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde résultats {module_name}: {e}")
            return None

    def get_module_results(self, task_id: str, module_name: str = None) -> List[Dict]:
        """Récupère les résultats d'un ou plusieurs modules pour une tâche"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if module_name:
                    cursor.execute('''
                        SELECT * FROM module_results 
                        WHERE task_id = ? AND module_name = ?
                        ORDER BY created_at DESC
                    ''', (task_id, module_name))
                else:
                    cursor.execute('''
                        SELECT * FROM module_results 
                        WHERE task_id = ?
                        ORDER BY created_at DESC
                    ''', (task_id,))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Désérialiser le JSON
                    try:
                        result['result_data'] = json.loads(result['result_data'])
                    except json.JSONDecodeError:
                        result['result_data'] = {}
                    results.append(result)
                
                return results
        except Exception as e:
            logger.error(f"❌ Erreur récupération résultats {task_id}: {e}")
            return []

    def get_audit_summary(self, task_id: str) -> Dict:
        """Génère un résumé complet d'un audit de pentest"""
        try:
            # Récupérer les informations de base de la tâche
            task = self.get_task_by_id(task_id)
            if not task:
                return {}
            
            # Récupérer tous les résultats de modules
            module_results = self.get_module_results(task_id)
            
            # Compiler le résumé
            summary = {
                'task_id': task_id,
                'task_name': task['task_name'],
                'target': task['target'],
                'started_at': task['started_at'],
                'completed_at': task['completed_at'],
                'status': task['status'],
                'modules_executed': [],
                'total_hosts_found': 0,
                'total_ports_found': 0,
                'total_services_found': 0,
                'vulnerabilities_found': 0,
                'credentials_found': 0
            }
            
            # Analyser chaque module
            for module_result in module_results:
                module_name = module_result['module_name']
                result_data = module_result['result_data']
                
                module_summary = {
                    'module': module_name,
                    'success': result_data.get('success', False),
                    'timestamp': module_result['created_at']
                }
                
                # Découverte réseau
                if module_name == 'network_discovery':
                    hosts_found = result_data.get('hosts_found', 0)
                    summary['total_hosts_found'] = hosts_found
                    module_summary['hosts_discovered'] = hosts_found
                
                # Scan de ports
                elif module_name == 'port_scan':
                    total_ports = result_data.get('total_open_ports', 0)
                    hosts_with_ports = result_data.get('hosts_with_open_ports', 0)
                    summary['total_ports_found'] = total_ports
                    module_summary['ports_found'] = total_ports
                    module_summary['hosts_with_ports'] = hosts_with_ports
                
                # Énumération de services
                elif module_name == 'service_enumeration':
                    services = result_data.get('total_services', 0)
                    summary['total_services_found'] = services
                    module_summary['services_identified'] = services
                
                # Scan de vulnérabilités
                elif module_name == 'vulnerability_scan':
                    vulns = result_data.get('vulnerabilities_found', 0)
                    summary['vulnerabilities_found'] += vulns
                    module_summary['vulnerabilities'] = vulns
                
                # Exploitation
                elif module_name == 'exploitation':
                    creds = len(result_data.get('credentials_found', []))
                    summary['credentials_found'] += creds
                    module_summary['credentials_obtained'] = creds
                
                summary['modules_executed'].append(module_summary)
            
            return summary
            
        except Exception as e:
            logger.error(f"❌ Erreur génération résumé audit {task_id}: {e}")
            return {}

    def get_pentest_statistics(self) -> Dict:
        """Récupère des statistiques globales sur les pentests"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Statistiques par module
                cursor.execute('''
                    SELECT module_name, COUNT(*) as count
                    FROM module_results
                    GROUP BY module_name
                ''')
                
                module_stats = {row['module_name']: row['count'] for row in cursor.fetchall()}
                stats['modules_usage'] = module_stats
                
                # Statistiques temporelles (derniers 30 jours)
                cursor.execute('''
                    SELECT DATE(created_at) as date, COUNT(*) as scans
                    FROM module_results
                    WHERE created_at >= datetime('now', '-30 days')
                    GROUP BY DATE(created_at)
                    ORDER BY date DESC
                ''')
                
                daily_stats = {row['date']: row['scans'] for row in cursor.fetchall()}
                stats['daily_activity'] = daily_stats
                
                # Top des cibles scannées
                cursor.execute('''
                    SELECT target, COUNT(*) as scan_count
                    FROM module_results
                    WHERE target IS NOT NULL AND target != ''
                    GROUP BY target
                    ORDER BY scan_count DESC
                    LIMIT 10
                ''')
                
                top_targets = [(row['target'], row['scan_count']) for row in cursor.fetchall()]
                stats['top_targets'] = top_targets
                
                return stats
                
        except Exception as e:
            logger.error(f"❌ Erreur statistiques pentest: {e}")
            return {}

    def export_audit_results(self, task_id: str, format: str = 'json') -> Dict:
        """Exporte tous les résultats d'un audit dans un format donné"""
        try:
            # Récupérer le résumé complet
            summary = self.get_audit_summary(task_id)
            
            # Récupérer tous les résultats détaillés
            module_results = self.get_module_results(task_id)
            
            export_data = {
                'audit_summary': summary,
                'detailed_results': module_results,
                'export_timestamp': datetime.now().isoformat(),
                'export_format': format
            }
            
            if format == 'json':
                return export_data
            elif format == 'xml':
                # Conversion XML (à implémenter si nécessaire)
                return {'error': 'Format XML non encore implémenté'}
            else:
                return {'error': f'Format {format} non supporté'}
                
        except Exception as e:
            logger.error(f"❌ Erreur export audit {task_id}: {e}")
            return {'error': str(e)}
    
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
                AND status IN ('completed', 'failed', 'cancelled')
                AND hidden = 0
            '''.format(days))
            conn.commit()
            return cursor.rowcount
    
    def cleanup_all_completed_tasks(self) -> int:
        """Supprime toutes les tâches terminées (completed, failed, cancelled)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE tasks SET hidden = 1
                WHERE status IN ('completed', 'failed', 'cancelled')
                AND hidden = 0
            ''')
            conn.commit()
            return cursor.rowcount

    def cleanup_module_results(self, days: int = 30) -> int:
        """Nettoie les anciens résultats de modules"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM module_results
                    WHERE created_at < datetime('now', '-{} days')
                '''.format(days))
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            logger.error(f"❌ Erreur nettoyage résultats modules: {e}")
            return 0

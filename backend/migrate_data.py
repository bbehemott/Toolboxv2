#!/usr/bin/env python3
"""
Script de migration depuis les 3 anciennes BDD vers la nouvelle BDD unifiée
"""
import sqlite3
import bcrypt
import os
from pathlib import Path
from database import DatabaseManager
from config import config

def migrate_from_old_databases():
    """Migre toutes les données depuis les anciennes BDD"""
    
    print("🔄 Début de la migration des données...")
    
    # Initialiser le nouveau gestionnaire BDD
    config_obj = config['development']
    new_db = DatabaseManager(config_obj.DATABASE_PATH)
    
    # Chemins vers les anciennes BDD (à adapter selon votre structure)
    old_users_db = "users.db"
    old_scans_db = "scans.db" 
    old_tasks_db = "tasks_history.db"
    
    migrated_count = 0
    
    # ===== MIGRATION UTILISATEURS =====
    if Path(old_users_db).exists():
        print(f"📂 Migration utilisateurs depuis {old_users_db}")
        try:
            old_conn = sqlite3.connect(old_users_db)
            old_conn.row_factory = sqlite3.Row
            
            cursor = old_conn.cursor()
            cursor.execute("SELECT * FROM users")
            old_users = cursor.fetchall()
            
            for user in old_users:
                # Vérifier si l'utilisateur existe déjà
                with new_db.get_connection() as new_conn:
                    new_cursor = new_conn.cursor()
                    new_cursor.execute("SELECT id FROM users WHERE username = ?", (user['username'],))
                    
                    if not new_cursor.fetchone():
                        # Créer l'utilisateur dans la nouvelle BDD
                        new_cursor.execute('''
                            INSERT INTO users (username, password_hash, role, created_at, last_login, active)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            user['username'],
                            user['password_hash'],
                            user.get('role', 'viewer'),
                            user.get('created_at', 'CURRENT_TIMESTAMP'),
                            user.get('last_login'),
                            user.get('active', 1)
                        ))
                        new_conn.commit()
                        migrated_count += 1
                        print(f"  ✅ Utilisateur migré: {user['username']}")
            
            old_conn.close()
            
        except Exception as e:
            print(f"  ❌ Erreur migration utilisateurs: {e}")
    else:
        print(f"  ⚠️ Fichier {old_users_db} introuvable")
    
    # ===== MIGRATION TÂCHES =====
    if Path(old_tasks_db).exists():
        print(f"📂 Migration tâches depuis {old_tasks_db}")
        try:
            old_conn = sqlite3.connect(old_tasks_db)
            old_conn.row_factory = sqlite3.Row
            
            cursor = old_conn.cursor()
            cursor.execute("SELECT * FROM tasks ORDER BY started_at DESC LIMIT 100")  # Limiter aux 100 dernières
            old_tasks = cursor.fetchall()
            
            for task in old_tasks:
                # Vérifier si la tâche existe déjà
                with new_db.get_connection() as new_conn:
                    new_cursor = new_conn.cursor()
                    new_cursor.execute("SELECT id FROM tasks WHERE task_id = ?", (task['task_id'],))
                    
                    if not new_cursor.fetchone():
                        new_cursor.execute('''
                            INSERT INTO tasks (task_id, task_name, task_type, target, status, progress, 
                                             user_id, started_at, completed_at, result_summary, error_message, hidden)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            task['task_id'],
                            task.get('task_name', 'Tâche migrée'),
                            task.get('task_type', 'unknown'),
                            task.get('target'),
                            task.get('status', 'completed'),
                            task.get('progress', 100),
                            task.get('user_id'),
                            task.get('started_at'),
                            task.get('completed_at'),
                            task.get('result_summary'),
                            task.get('error_message'),
                            0  # Pas caché
                        ))
                        new_conn.commit()
                        migrated_count += 1
                        print(f"  ✅ Tâche migrée: {task['task_id'][:8]}...")
            
            old_conn.close()
            
        except Exception as e:
            print(f"  ❌ Erreur migration tâches: {e}")
    else:
        print(f"  ⚠️ Fichier {old_tasks_db} introuvable")
    
    # ===== MIGRATION SCANS =====
    if Path(old_scans_db).exists():
        print(f"📂 Migration scans depuis {old_scans_db}")
        try:
            old_conn = sqlite3.connect(old_scans_db)
            old_conn.row_factory = sqlite3.Row
            
            cursor = old_conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT 50")  # Limiter aux 50 derniers
            old_scans = cursor.fetchall()
            
            for scan in old_scans:
                # Créer le scan dans la nouvelle BDD
                with new_db.get_connection() as new_conn:
                    new_cursor = new_conn.cursor()
                    new_cursor.execute('''
                        INSERT INTO scans (scan_name, target_ip, scan_type, openvas_task_id, 
                                         status, progress, user_id, started_at, completed_at, result_summary)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan.get('scan_name', 'Scan migré'),
                        scan.get('target_ip', 'Unknown'),
                        scan.get('scan_type', 'full_and_fast'),
                        scan.get('openvas_task_id'),
                        scan.get('status', 'completed'),
                        scan.get('progress', 100),
                        scan.get('user_id'),
                        scan.get('started_at'),
                        scan.get('completed_at'),
                        scan.get('result_summary')
                    ))
                    new_conn.commit()
                    migrated_count += 1
                    print(f"  ✅ Scan migré: {scan.get('scan_name', 'Sans nom')}")
            
            old_conn.close()
            
        except Exception as e:
            print(f"  ❌ Erreur migration scans: {e}")
    else:
        print(f"  ⚠️ Fichier {old_scans_db} introuvable")
    
    print(f"\n🎉 Migration terminée ! {migrated_count} éléments migrés.")
    print(f"📍 Nouvelle BDD: {config_obj.DATABASE_PATH}")
    
    # Afficher un résumé
    stats = new_db.get_stats()
    print(f"\n📊 Résumé de la nouvelle BDD:")
    print(f"   👥 Utilisateurs: {stats.get('active_users', 0)}")
    print(f"   📋 Tâches: {sum(stats.get('tasks', {}).values())}")
    print(f"   🔍 Scans: {sum(stats.get('scans', {}).values())}")

if __name__ == "__main__":
    migrate_from_old_databases()

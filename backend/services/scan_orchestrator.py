# backend/services/scan_orchestrator.py - Orchestrateur de scans OpenVAS
import time
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger('toolbox.scan_orchestrator')

class ScanOrchestrator:
    """Orchestrateur pour les scans OpenVAS et autres scanners"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self._openvas_wrapper = None
    
    @property
    def openvas(self):
        """Lazy loading du wrapper OpenVAS"""
        if self._openvas_wrapper is None:
            from core.openvas_wrapper import OpenVASWrapper
            self._openvas_wrapper = OpenVASWrapper()
        return self._openvas_wrapper
    
    # ===== LANCEMENT DE SCANS =====
    
    def start_openvas_scan(self, target: str, scan_name: str, scan_type: str, user_id: int) -> Optional[int]:
        """Lance un scan OpenVAS complet"""
        try:
            logger.info(f"Lancement scan OpenVAS: {scan_name} sur {target}")
            
            # Étape 1: Créer la cible dans OpenVAS
            target_id = self._create_openvas_target(target, scan_name)
            if not target_id:
                logger.error("Impossible de créer la cible OpenVAS")
                return None
            
            # Étape 2: Récupérer la configuration de scan
            config_id = self._get_scan_config(scan_type)
            if not config_id:
                logger.error(f"Configuration de scan '{scan_type}' non trouvée")
                return None
            
            # Étape 3: Créer la tâche OpenVAS
            openvas_task_id = self._create_openvas_task(scan_name, target_id, config_id)
            if not openvas_task_id:
                logger.error("Impossible de créer la tâche OpenVAS")
                return None
            
            # Étape 4: Enregistrer en base de données
            scan_id = self.db.create_scan(
                scan_name=scan_name,
                target_ip=target,
                scan_type=scan_type,
                openvas_task_id=openvas_task_id,
                user_id=user_id
            )
            
            # Étape 5: Démarrer le scan
            if self._start_openvas_task(openvas_task_id):
                self.db.update_scan_status(scan_id, 'running', 0)
                logger.info(f"Scan OpenVAS démarré avec succès: {scan_id}")
                return scan_id
            else:
                logger.error("Impossible de démarrer le scan OpenVAS")
                self.db.update_scan_status(scan_id, 'failed', 0)
                return None
                
        except Exception as e:
            logger.error(f"Erreur lancement scan OpenVAS: {e}")
            return None
    
    def _create_openvas_target(self, target_ip: str, scan_name: str) -> Optional[str]:
        """Crée une cible dans OpenVAS"""
        try:
            # Vérifier si la cible existe déjà
            existing_targets = self.openvas.list_targets()
            for existing_target in existing_targets:
                if existing_target['hosts'] == target_ip:
                    logger.info(f"Cible existante trouvée: {existing_target['id']}")
                    return existing_target['id']
            
            # Créer une nouvelle cible
            target_name = f"{scan_name}_target"
            target_id = self.openvas.create_target(target_name, target_ip)
            
            if target_id:
                logger.info(f"Nouvelle cible OpenVAS créée: {target_id}")
                return target_id
            else:
                logger.error("Échec création cible OpenVAS")
                return None
                
        except Exception as e:
            logger.error(f"Erreur création cible OpenVAS: {e}")
            return None
    
    def _get_scan_config(self, scan_type: str) -> Optional[str]:
        """Récupère l'ID de configuration de scan OpenVAS"""
        try:
            configs = self.openvas.list_configs()
            
            # Mapping des types de scan
            config_mapping = {
                'discovery': ['Discovery', 'Host Discovery'],
                'full_and_fast': ['Full and fast'],
                'full_and_very_deep': ['Full and very deep', 'Ultimate'],
                'system_discovery': ['System Discovery'],
                'host_discovery': ['Host Discovery']
            }
            
            search_terms = config_mapping.get(scan_type, ['Full and fast'])
            
            for config in configs:
                config_name_lower = config['name'].lower()
                for term in search_terms:
                    if term.lower() in config_name_lower:
                        logger.info(f"Configuration trouvée: {config['name']} ({config['id']})")
                        return config['id']
            
            # Fallback sur la première configuration disponible
            if configs:
                fallback_config = configs[0]
                logger.warning(f"Configuration par défaut utilisée: {fallback_config['name']}")
                return fallback_config['id']
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur récupération config scan: {e}")
            return None
    
    def _create_openvas_task(self, scan_name: str, target_id: str, config_id: str) -> Optional[str]:
        """Crée une tâche de scan dans OpenVAS"""
        try:
            task_id = self.openvas.create_task(scan_name, target_id, config_id)
            
            if task_id:
                logger.info(f"Tâche OpenVAS créée: {task_id}")
                return task_id
            else:
                logger.error("Échec création tâche OpenVAS")
                return None
                
        except Exception as e:
            logger.error(f"Erreur création tâche OpenVAS: {e}")
            return None
    
    def _start_openvas_task(self, task_id: str) -> bool:
        """Démarre une tâche OpenVAS"""
        try:
            success = self.openvas.start_task(task_id)
            
            if success:
                logger.info(f"Tâche OpenVAS démarrée: {task_id}")
                return True
            else:
                logger.error(f"Échec démarrage tâche OpenVAS: {task_id}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur démarrage tâche OpenVAS: {e}")
            return False
    
    # ===== GESTION DES SCANS =====
    
    def get_scan_details(self, scan_id: int, user_id: int, user_role: str) -> Optional[Dict]:
        """Récupère les détails d'un scan"""
        try:
            scans = self.db.get_scans()
            scan = next((s for s in scans if s['id'] == scan_id), None)
            
            if not scan:
                return None
            
            # Vérifier les droits d'accès
            if not self._can_user_access_scan(scan, user_id, user_role):
                return None
            
            # Enrichir avec les informations OpenVAS
            if scan['openvas_task_id']:
                openvas_status = self.openvas.get_task_status(scan['openvas_task_id'])
                if openvas_status:
                    scan['openvas_status'] = openvas_status
                    
                    # Mettre à jour le statut en base si nécessaire
                    if openvas_status['status'] != scan['status']:
                        self.db.update_scan_status(
                            scan_id, 
                            openvas_status['status'], 
                            openvas_status.get('progress', scan['progress'])
                        )
            
            return scan
            
        except Exception as e:
            logger.error(f"Erreur détails scan {scan_id}: {e}")
            return None
    
    def get_active_scans_status(self, user_id: int, user_role: str) -> List[Dict]:
        """Récupère le statut des scans actifs et met à jour la base"""
        try:
            # Récupérer les scans actifs
            if user_role == 'admin':
                active_scans = self.db.get_scans(active_only=True)
            else:
                active_scans = self.db.get_scans(user_id=user_id, active_only=True)
            
            updated_scans = []
            
            for scan in active_scans:
                if scan['openvas_task_id']:
                    # Récupérer le statut depuis OpenVAS
                    openvas_status = self.openvas.get_task_status(scan['openvas_task_id'])
                    
                    if openvas_status:
                        # Mettre à jour en base si le statut a changé
                        if (openvas_status['status'] != scan['status'] or 
                            openvas_status.get('progress', 0) != scan['progress']):
                            
                            self.db.update_scan_status(
                                scan['id'],
                                openvas_status['status'],
                                openvas_status.get('progress', 0)
                            )
                            
                            # Mettre à jour le scan local
                            scan['status'] = openvas_status['status']
                            scan['progress'] = openvas_status.get('progress', 0)
                
                updated_scans.append(scan)
            
            return updated_scans
            
        except Exception as e:
            logger.error(f"Erreur statut scans actifs: {e}")
            return []
    
    def pause_scan(self, scan_id: int, user_id: int, user_role: str) -> bool:
        """Met en pause un scan"""
        try:
            scan = self.get_scan_details(scan_id, user_id, user_role)
            if not scan or not scan['openvas_task_id']:
                return False
            
            success = self.openvas.stop_task(scan['openvas_task_id'])
            
            if success:
                self.db.update_scan_status(scan_id, 'paused')
                logger.info(f"Scan mis en pause: {scan_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur pause scan {scan_id}: {e}")
            return False
    
    def resume_scan(self, scan_id: int, user_id: int, user_role: str) -> bool:
        """Reprend un scan en pause"""
        try:
            scan = self.get_scan_details(scan_id, user_id, user_role)
            if not scan or not scan['openvas_task_id']:
                return False
            
            success = self.openvas.start_task(scan['openvas_task_id'])
            
            if success:
                self.db.update_scan_status(scan_id, 'running')
                logger.info(f"Scan repris: {scan_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur reprise scan {scan_id}: {e}")
            return False
    
    def stop_scan(self, scan_id: int, user_id: int, user_role: str) -> bool:
        """Arrête définitivement un scan"""
        try:
            scan = self.get_scan_details(scan_id, user_id, user_role)
            if not scan or not scan['openvas_task_id']:
                return False
            
            success = self.openvas.stop_task(scan['openvas_task_id'])
            
            if success:
                self.db.update_scan_status(scan_id, 'stopped')
                logger.info(f"Scan arrêté: {scan_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur arrêt scan {scan_id}: {e}")
            return False
    
    def delete_scan(self, scan_id: int, user_id: int, user_role: str) -> bool:
        """Supprime un scan (marque comme caché)"""
        try:
            scan = self.get_scan_details(scan_id, user_id, user_role)
            if not scan:
                return False
            
            # Marquer comme caché en base
            success = self.db.hide_scan(scan_id)
            
            if success:
                logger.info(f"Scan masqué: {scan_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur suppression scan {scan_id}: {e}")
            return False
    
    def get_scan_results(self, scan_id: int, user_id: int, user_role: str) -> Optional[Dict]:
        """Récupère les résultats d'un scan terminé"""
        try:
            scan = self.get_scan_details(scan_id, user_id, user_role)
            if not scan or not scan['openvas_task_id']:
                return None
            
            # Vérifier que le scan est terminé
            if scan['status'] not in ['completed', 'finished', 'done']:
                return {
                    'success': False,
                    'message': f'Scan pas encore terminé (statut: {scan["status"]})'
                }
            
            # Récupérer les résultats depuis OpenVAS
            results = self.openvas.get_task_results(scan['openvas_task_id'])
            
            if results:
                return {
                    'success': True,
                    'scan_info': scan,
                    'results': results
                }
            else:
                return {
                    'success': False,
                    'message': 'Résultats non disponibles'
                }
                
        except Exception as e:
            logger.error(f"Erreur résultats scan {scan_id}: {e}")
            return {
                'success': False,
                'message': f'Erreur: {str(e)}'
            }
    
    # ===== CONFIGURATION ET UTILITAIRES =====
    
    def get_available_scan_configs(self) -> List[Dict]:
        """Récupère les configurations de scan disponibles"""
        try:
            configs = self.openvas.list_configs()
            
            # Enrichir avec des descriptions
            enhanced_configs = []
            for config in configs:
                enhanced_config = config.copy()
                
                # Ajouter des descriptions et estimations
                config_name_lower = config['name'].lower()
                if 'discovery' in config_name_lower:
                    enhanced_config['description'] = 'Découverte rapide des hôtes'
                    enhanced_config['estimated_duration'] = '5-10 minutes'
                elif 'full and fast' in config_name_lower:
                    enhanced_config['description'] = 'Scan complet optimisé'
                    enhanced_config['estimated_duration'] = '15-30 minutes'
                elif 'full and very deep' in config_name_lower or 'ultimate' in config_name_lower:
                    enhanced_config['description'] = 'Scan très approfondi'
                    enhanced_config['estimated_duration'] = '45-90 minutes'
                else:
                    enhanced_config['description'] = 'Configuration personnalisée'
                    enhanced_config['estimated_duration'] = '15-45 minutes'
                
                enhanced_configs.append(enhanced_config)
            
            return enhanced_configs
            
        except Exception as e:
            logger.error(f"Erreur récupération configs: {e}")
            return []
    
    def validate_target_for_openvas(self, target: str) -> Dict:
        """Validations supplémentaires spécifiques à OpenVAS"""
        try:
            checks = {
                'ping_test': False,
                'port_check': False,
                'warnings': []
            }
            
            # Test de ping simple
            import subprocess
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '2', target], 
                                      capture_output=True, timeout=5)
                checks['ping_test'] = result.returncode == 0
            except:
                checks['ping_test'] = False
            
            if not checks['ping_test']:
                checks['warnings'].append('Cible ne répond pas au ping')
            
            # Test de ports communs
            import socket
            common_ports = [22, 80, 443, 3389]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((target, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            checks['port_check'] = len(open_ports) > 0
            checks['open_ports'] = open_ports
            
            if not checks['port_check']:
                checks['warnings'].append('Aucun port commun ouvert détecté')
            
            return checks
            
        except Exception as e:
            logger.error(f"Erreur validation cible OpenVAS: {e}")
            return {'ping_test': False, 'port_check': False, 'warnings': [str(e)]}
    
    def _can_user_access_scan(self, scan: Dict, user_id: int, user_role: str) -> bool:
        """Vérifie si un utilisateur peut accéder à un scan"""
        # Admin voit tout
        if user_role == 'admin':
            return True
        
        # L'utilisateur voit ses propres scans
        return scan.get('user_id') == user_id
    
    # ===== MAINTENANCE =====
    
    def sync_openvas_status(self) -> int:
        """Synchronise le statut des scans actifs avec OpenVAS"""
        try:
            active_scans = self.db.get_scans(active_only=True)
            synced_count = 0
            
            for scan in active_scans:
                if scan['openvas_task_id']:
                    openvas_status = self.openvas.get_task_status(scan['openvas_task_id'])
                    
                    if openvas_status and openvas_status['status'] != scan['status']:
                        self.db.update_scan_status(
                            scan['id'],
                            openvas_status['status'],
                            openvas_status.get('progress', scan['progress'])
                        )
                        synced_count += 1
            
            if synced_count > 0:
                logger.info(f"Synchronisation: {synced_count} scans mis à jour")
            
            return synced_count
            
        except Exception as e:
            logger.error(f"Erreur synchronisation OpenVAS: {e}")
            return 0

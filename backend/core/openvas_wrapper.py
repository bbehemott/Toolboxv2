import subprocess
import xml.etree.ElementTree as ET
import re
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger('toolbox.openvas')

class OpenVASWrapper:
    """Wrapper intelligent pour OpenVAS/GVM via OMP"""
    
    def __init__(self, host='openvas', port=9390, username='admin', password='admin'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = 60
    
    def _run_omp_command(self, args: List[str]) -> subprocess.CompletedProcess:
        """Exécute une commande OMP"""
        try:
            cmd = [
                'docker', 'exec', 'openvas',
                'omp', '--username', self.username, '--password', self.password
            ] + args
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout commande OMP: {args}")
            raise
        except Exception as e:
            logger.error(f"Erreur commande OMP {args}: {e}")
            raise
    
    def test_connection(self) -> bool:
        """Test de connectivité avec OpenVAS"""
        try:
            result = self._run_omp_command(['--ping'])
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Test connexion OpenVAS échoué: {e}")
            return False
    
    # ===== GESTION DES CIBLES =====
    
    def list_targets(self) -> List[Dict]:
        """Liste toutes les cibles"""
        try:
            result = self._run_omp_command(['-T'])
            
            if result.returncode != 0:
                logger.error(f"Erreur liste cibles: {result.stderr}")
                return []
            
            targets = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('ID'):
                    parts = line.split()
                    if len(parts) >= 2:
                        target_id = parts[0]
                        target_name = ' '.join(parts[1:])
                        
                        # Récupérer les détails de la cible
                        details = self._get_target_details(target_id)
                        targets.append({
                            'id': target_id,
                            'name': target_name,
                            'hosts': details.get('hosts', ''),
                            'created': details.get('created', ''),
                            'modified': details.get('modified', '')
                        })
            
            return targets
            
        except Exception as e:
            logger.error(f"Erreur liste cibles: {e}")
            return []
    
    def create_target(self, name: str, hosts: str, comment: str = '') -> Optional[str]:
        """Crée une nouvelle cible"""
        try:
            # Construire la commande XML
            xml_cmd = f'<create_target><name>{name}</name><hosts>{hosts}</hosts>'
            if comment:
                xml_cmd += f'<comment>{comment}</comment>'
            xml_cmd += '</create_target>'
            
            result = self._run_omp_command(['--xml=' + xml_cmd])
            
            if result.returncode == 0:
                # Extraire l'ID de la réponse
                target_id = self._extract_id_from_response(result.stdout)
                if target_id:
                    logger.info(f"Cible créée: {name} ({target_id})")
                    return target_id
            
            logger.error(f"Échec création cible: {result.stderr}")
            return None
            
        except Exception as e:
            logger.error(f"Erreur création cible {name}: {e}")
            return None
    
    def _get_target_details(self, target_id: str) -> Dict:
        """Récupère les détails d'une cible"""
        try:
            result = self._run_omp_command(['--get-targets', target_id])
            
            if result.returncode == 0:
                # Parser la sortie XML
                return self._parse_target_xml(result.stdout)
            
            return {}
            
        except Exception as e:
            logger.error(f"Erreur détails cible {target_id}: {e}")
            return {}
    
    # ===== GESTION DES CONFIGURATIONS =====
    
    def list_configs(self) -> List[Dict]:
        """Liste les configurations de scan disponibles"""
        try:
            result = self._run_omp_command(['-g'])
            
            if result.returncode != 0:
                logger.error(f"Erreur liste configs: {result.stderr}")
                return []
            
            configs = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('ID'):
                    parts = line.split(None, 1)  # Split en 2 parties max
                    if len(parts) >= 2:
                        config_id = parts[0]
                        config_name = parts[1]
                        
                        configs.append({
                            'id': config_id,
                            'name': config_name
                        })
            
            return configs
            
        except Exception as e:
            logger.error(f"Erreur liste configs: {e}")
            return []
    
    # ===== GESTION DES TÂCHES =====
    
    def create_task(self, name: str, target_id: str, config_id: str, comment: str = '') -> Optional[str]:
        """Crée une nouvelle tâche de scan"""
        try:
            args = ['-C', '-c', config_id, '--name', name, f'--target={target_id}']
            if comment:
                args.extend(['--comment', comment])
            
            result = self._run_omp_command(args)
            
            if result.returncode == 0:
                task_id = result.stdout.strip()
                if task_id:
                    logger.info(f"Tâche créée: {name} ({task_id})")
                    return task_id
            
            logger.error(f"Échec création tâche: {result.stderr}")
            return None
            
        except Exception as e:
            logger.error(f"Erreur création tâche {name}: {e}")
            return None
    
    def start_task(self, task_id: str) -> bool:
        """Démarre une tâche"""
        try:
            result = self._run_omp_command(['-S', task_id])
            
            if result.returncode == 0:
                logger.info(f"Tâche démarrée: {task_id}")
                return True
            else:
                logger.error(f"Échec démarrage tâche {task_id}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur démarrage tâche {task_id}: {e}")
            return False
    
    def stop_task(self, task_id: str) -> bool:
        """Arrête une tâche"""
        try:
            xml_cmd = f'<stop_task task_id="{task_id}"/>'
            result = self._run_omp_command(['--xml=' + xml_cmd])
            
            if result.returncode == 0:
                logger.info(f"Tâche arrêtée: {task_id}")
                return True
            else:
                logger.error(f"Échec arrêt tâche {task_id}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur arrêt tâche {task_id}: {e}")
            return False
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Récupère le statut d'une tâche"""
        try:
            result = self._run_omp_command(['-G'])
            
            if result.returncode != 0:
                return None
            
            # Chercher la tâche dans la sortie
            for line in result.stdout.split('\n'):
                if task_id in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        status = parts[1]
                        progress_str = parts[2]
                        
                        # Extraire le pourcentage
                        progress = 0
                        progress_match = re.search(r'(\d+)%', progress_str)
                        if progress_match:
                            progress = int(progress_match.group(1))
                        
                        # Mapper les statuts OpenVAS
                        status_mapping = {
                            'Running': 'running',
                            'Done': 'completed',
                            'Stopped': 'stopped',
                            'Requested': 'pending',
                            'Stop Requested': 'stopping',
                            'New': 'created'
                        }
                        
                        mapped_status = status_mapping.get(status, status.lower())
                        
                        return {
                            'task_id': task_id,
                            'status': mapped_status,
                            'progress': progress,
                            'raw_status': status
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur statut tâche {task_id}: {e}")
            return None
    
    def list_tasks(self) -> List[Dict]:
        """Liste toutes les tâches"""
        try:
            result = self._run_omp_command(['-G'])
            
            if result.returncode != 0:
                return []
            
            tasks = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('ID'):
                    parts = line.split()
                    if len(parts) >= 4:
                        task_id = parts[0]
                        status = parts[1]
                        progress = parts[2]
                        name = ' '.join(parts[3:])
                        
                        tasks.append({
                            'id': task_id,
                            'name': name,
                            'status': status,
                            'progress': progress
                        })
            
            return tasks
            
        except Exception as e:
            logger.error(f"Erreur liste tâches: {e}")
            return []
    
    # ===== GESTION DES RÉSULTATS =====
    
    def get_task_results(self, task_id: str) -> Optional[Dict]:
        """Récupère les résultats d'une tâche terminée"""
        try:
            # Récupérer les détails de la tâche pour avoir l'ID du rapport
            task_details = self._run_omp_command(['--get-tasks', task_id])
            
            if task_details.returncode != 0:
                return None
            
            # Extraire l'ID du rapport
            report_id = self._extract_report_id_from_task(task_details.stdout)
            if not report_id:
                return None
            
            # Récupérer le rapport
            report_result = self._run_omp_command(['-R', report_id])
            
            if report_result.returncode != 0:
                return None
            
            # Parser les résultats
            return self._parse_report_results(report_result.stdout)
            
        except Exception as e:
            logger.error(f"Erreur résultats tâche {task_id}: {e}")
            return None
    
    # ===== MÉTHODES UTILITAIRES =====
    
    def _extract_id_from_response(self, xml_response: str) -> Optional[str]:
        """Extrait un ID d'une réponse XML"""
        try:
            # Chercher l'attribut id dans la réponse
            id_match = re.search(r'id="([^"]+)"', xml_response)
            if id_match:
                return id_match.group(1)
            
            # Fallback: chercher un UUID dans la réponse
            uuid_match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', xml_response)
            if uuid_match:
                return uuid_match.group(1)
            
            return None
            
        except Exception:
            return None
    
    def _extract_report_id_from_task(self, task_xml: str) -> Optional[str]:
        """Extrait l'ID du rapport d'une tâche"""
        try:
            # Chercher les UUID dans la sortie (le rapport est généralement le 2ème UUID)
            uuids = re.findall(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', task_xml)
            
            # Le premier UUID est généralement la tâche, le second le rapport
            if len(uuids) >= 2:
                return uuids[1]
            
            return None
            
        except Exception:
            return None
    
    def _parse_target_xml(self, xml_content: str) -> Dict:
        """Parse les détails d'une cible depuis XML"""
        try:
            # Parsing basique pour extraire les infos principales
            details = {}
            
            hosts_match = re.search(r'<hosts>([^<]+)</hosts>', xml_content)
            if hosts_match:
                details['hosts'] = hosts_match.group(1)
            
            return details
            
        except Exception:
            return {}
    
    def _parse_report_results(self, report_content: str) -> Dict:
        """Parse les résultats d'un rapport"""
        try:
            results = {
                'total': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'vulnerabilities': [],
                'summary': 'Analyse terminée'
            }
            
            # Compter les vulnérabilités par niveau
            high_count = len(re.findall(r'<threat>High</threat>', report_content, re.IGNORECASE))
            medium_count = len(re.findall(r'<threat>Medium</threat>', report_content, re.IGNORECASE))
            low_count = len(re.findall(r'<threat>Low</threat>', report_content, re.IGNORECASE))
            
            results['high'] = high_count
            results['medium'] = medium_count
            results['low'] = low_count
            results['total'] = high_count + medium_count + low_count
            
            # Extraire les noms des vulnérabilités
            vuln_names = []
            
            # Chercher les noms des vulnérabilités dans les résultats
            result_pattern = r'<result[^>]*>(.*?)</result>'
            result_blocks = re.findall(result_pattern, report_content, re.DOTALL | re.IGNORECASE)
            
            for result_block in result_blocks:
                # Chercher le niveau de menace
                threat_match = re.search(r'<threat>(.*?)</threat>', result_block, re.IGNORECASE)
                if threat_match and threat_match.group(1) in ['High', 'Medium', 'Low']:
                    threat_level = threat_match.group(1)
                    
                    # Chercher le nom de la vulnérabilité
                    name_match = re.search(r'<name>(.*?)</name>', result_block, re.IGNORECASE)
                    if name_match:
                        vuln_name = name_match.group(1).strip()
                        
                        # Nettoyer le nom
                        clean_name = re.sub(r'<[^>]+>', '', vuln_name).strip()
                        clean_name = re.sub(r'\s+', ' ', clean_name)
                        
                        if clean_name and len(clean_name) > 3:
                            emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🔵'}
                            vuln_names.append(f"{emoji.get(threat_level, '⚪')} {clean_name}")
            
            # Limiter à 10 vulnérabilités
            results['vulnerabilities'] = vuln_names[:10]
            
            # Créer un résumé
            if results['total'] == 0:
                results['summary'] = "🎉 Aucune vulnérabilité détectée"
            else:
                results['summary'] = f"Trouvé {results['total']} vulnérabilité(s): {high_count} élevées, {medium_count} moyennes, {low_count} faibles"
            
            return results
            
        except Exception as e:
            logger.error(f"Erreur parsing rapport: {e}")
            return {
                'total': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'vulnerabilities': [],
                'summary': 'Erreur lors de l\'analyse des résultats'
            }
    
    # ===== MÉTHODES AVANCÉES =====
    
    def delete_task(self, task_id: str, ultimate: bool = False) -> bool:
        """Supprime une tâche"""
        try:
            ultimate_flag = "1" if ultimate else "0"
            xml_cmd = f'<delete_task task_id="{task_id}" ultimate="{ultimate_flag}"/>'
            result = self._run_omp_command(['--xml=' + xml_cmd])
            
            if result.returncode == 0 and 'status="200"' in result.stdout:
                logger.info(f"Tâche supprimée: {task_id}")
                return True
            else:
                logger.error(f"Échec suppression tâche {task_id}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur suppression tâche {task_id}: {e}")
            return False
    
    def get_version_info(self) -> Dict:
        """Récupère les informations de version"""
        try:
            result = self._run_omp_command(['--get-version'])
            
            if result.returncode == 0:
                return {
                    'version': result.stdout.strip(),
                    'connected': True
                }
            else:
                return {
                    'version': 'Unknown',
                    'connected': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            return {
                'version': 'Unknown',
                'connected': False,
                'error': str(e)
            }
    
    def cleanup_old_tasks(self, days: int = 7) -> int:
        """Nettoie les anciennes tâches terminées"""
        try:
            tasks = self.list_tasks()
            deleted_count = 0
            
            for task in tasks:
                if task['status'].lower() in ['done', 'stopped']:
                    if self.delete_task(task['id']):
                        deleted_count += 1
            
            logger.info(f"Nettoyage OpenVAS: {deleted_count} tâches supprimées")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Erreur nettoyage OpenVAS: {e}")
            return 0
    
    # ===== MÉTHODES DE DIAGNOSTIC =====
    
    def diagnose_connection(self) -> Dict:
        """Diagnostic complet de la connexion OpenVAS"""
        diagnosis = {
            'openvas_container': False,
            'omp_service': False,
            'authentication': False,
            'targets_accessible': False,
            'configs_accessible': False,
            'overall_status': 'failed'
        }
        
        try:
            # Test 1: Vérifier que le container OpenVAS existe
            container_check = subprocess.run(
                ['docker', 'ps', '--filter', 'name=openvas', '--format', '{{.Names}}'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'openvas' in container_check.stdout:
                diagnosis['openvas_container'] = True
            
            # Test 2: Test de ping OMP
            if diagnosis['openvas_container']:
                ping_result = self._run_omp_command(['--ping'])
                diagnosis['omp_service'] = ping_result.returncode == 0
            
            # Test 3: Test d'authentification
            if diagnosis['omp_service']:
                version_info = self.get_version_info()
                diagnosis['authentication'] = version_info['connected']
            
            # Test 4: Accès aux cibles
            if diagnosis['authentication']:
                targets = self.list_targets()
                diagnosis['targets_accessible'] = isinstance(targets, list)
            
            # Test 5: Accès aux configurations
            if diagnosis['targets_accessible']:
                configs = self.list_configs()
                diagnosis['configs_accessible'] = isinstance(configs, list) and len(configs) > 0
            
            # Statut global
            if all([diagnosis['openvas_container'], diagnosis['omp_service'], 
                   diagnosis['authentication'], diagnosis['targets_accessible'], 
                   diagnosis['configs_accessible']]):
                diagnosis['overall_status'] = 'healthy'
            elif diagnosis['authentication']:
                diagnosis['overall_status'] = 'partial'
            else:
                diagnosis['overall_status'] = 'failed'
            
        except Exception as e:
            diagnosis['error'] = str(e)
            logger.error(f"Erreur diagnostic OpenVAS: {e}")
        
        return diagnosis

from flask import Blueprint, render_template, jsonify, current_app
from auth import login_required, admin_required
import requests
import logging
import psutil
import docker
from datetime import datetime, timedelta

logger = logging.getLogger('toolbox.monitoring')

monitoring_bp = Blueprint('monitoring', __name__)

# ===== ROUTES DU DASHBOARD MONITORING =====

@monitoring_bp.route('/')
@login_required
def monitoring_dashboard():
    """Dashboard de monitoring principal - Tâche 39"""
    return render_template('monitoring/dashboard.html')

@monitoring_bp.route('/api/system-health')
@login_required
def api_system_health():
    """API pour récupérer la santé du système"""
    try:
        health_data = {
            'timestamp': datetime.now().isoformat(),
            'system': get_system_metrics(),
            'services': get_services_status(),
            'storage': get_storage_metrics(),
            'logs': get_recent_logs_stats(),
            'alerts': get_active_alerts()
        }
        
        return {
            'success': True,
            'data': health_data
        }
        
    except Exception as e:
        logger.error(f"Erreur récupération santé système: {e}")
        return {
            'success': False,
            'error': str(e)
        }

@monitoring_bp.route('/api/services-status')
@login_required
def api_services_status():
    """Status détaillé des services"""
    try:
        services = get_services_status()
        return {
            'success': True,
            'services': services,
            'summary': {
                'total': len(services),
                'healthy': len([s for s in services if s['status'] == 'healthy']),
                'unhealthy': len([s for s in services if s['status'] != 'healthy'])
            }
        }
    except Exception as e:
        logger.error(f"Erreur status services: {e}")
        return {'success': False, 'error': str(e)}

@monitoring_bp.route('/api/logs-summary')
@login_required
def api_logs_summary():
    """Résumé des logs récents"""
    try:
        logs_data = get_recent_logs_stats()
        return {
            'success': True,
            'data': logs_data
        }
    except Exception as e:
        logger.error(f"Erreur résumé logs: {e}")
        return {'success': False, 'error': str(e)}

# ===== FONCTIONS UTILITAIRES =====
def get_system_metrics():
    """Métriques système (CPU, RAM, etc.)"""
    try:
        uptime_seconds = (datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds()
        
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'network': dict(psutil.net_io_counters()._asdict()),
            'uptime_seconds': uptime_seconds  # ← CHANGÉ : total_seconds() au lieu de timedelta
        }
    except Exception as e:
        logger.error(f"Erreur métriques système: {e}")
        return {'error': str(e)}


def get_services_status():
    """Status des services Docker - VERSION CORRIGÉE CONNECTIVITÉ"""
    services = []
    
    # Services essentiels à surveiller avec leurs vraies adresses Docker
    expected_services = [
        {
            'name': 'toolbox-app-huntkit', 
            'port': 5000, 
            'description': 'Application principale',
            'docker_host': 'app',  # Nom du service dans docker-compose
            'external_port': 5000
        },
        {
            'name': 'toolbox-graylog', 
            'port': 9000, 
            'description': 'Centralisation logs',
            'docker_host': 'graylog',
            'external_port': 9000
        },
        {
            'name': 'toolbox-kibana', 
            'port': 5601, 
            'description': 'Exploration logs',
            'docker_host': 'kibana',
            'external_port': 5601
        },
        {
            'name': 'toolbox-elasticsearch', 
            'port': 9200, 
            'description': 'Moteur de recherche',
            'docker_host': 'elasticsearch',
            'external_port': 9200
        },
        {
            'name': 'toolbox-postgres', 
            'port': 5432, 
            'description': 'Base de données',
            'docker_host': 'postgres',
            'external_port': 5432
        },
        {
            'name': 'toolbox-redis', 
            'port': 6379, 
            'description': 'Cache & broker',
            'docker_host': 'redis',
            'external_port': 6379
        },
        {
            'name': 'toolbox-minio', 
            'port': 9090, 
            'description': 'Stockage sécurisé',
            'docker_host': 'minio',
            'external_port': 9090
        },
        {
            'name': 'toolbox-worker-huntkit', 
            'port': None, 
            'description': 'Worker Celery',
            'docker_host': 'worker',
            'external_port': None
        },
        {
            'name': 'toolbox-metricbeat', 
            'port': None, 
            'description': 'Collecte métriques',
            'docker_host': 'metricbeat',
            'external_port': None
        }
    ]
    
    try:
        # Tenter de se connecter à Docker
        client = docker.from_env()
        containers = client.containers.list(all=True)
        
        for expected in expected_services:
            container_found = False
            
            for container in containers:
                if expected['name'] in container.name:
                    status = 'healthy' if container.status == 'running' else 'unhealthy'
                    
                    # Test connectivité CORRIGÉ - utiliser les noms Docker
                    connectivity = 'unknown'
                    if expected['port'] and container.status == 'running':
                        connectivity = test_service_connectivity(expected)
                    elif expected['port'] is None:
                        connectivity = 'n/a'
                    
                    services.append({
                        'name': expected['name'],
                        'description': expected['description'],
                        'status': status,
                        'docker_status': container.status,
                        'port': expected['port'],
                        'connectivity': connectivity,
                        'created': container.attrs.get('Created', ''),
                        'image': container.image.tags[0] if container.image.tags else 'unknown'
                    })
                    container_found = True
                    break
            
            if not container_found:
                services.append({
                    'name': expected['name'],
                    'description': expected['description'],
                    'status': 'missing',
                    'docker_status': 'not_found',
                    'port': expected['port'],
                    'connectivity': 'n/a'
                })
                
    except Exception as e:
        logger.error(f"Erreur Docker: {e}")
        
        # Fallback : test direct avec les bonnes adresses
        for expected in expected_services:
            if expected['port']:
                connectivity = test_service_connectivity(expected)
                status = 'healthy' if connectivity == 'ok' else 'unhealthy'
            else:
                status = 'unknown'
                connectivity = 'n/a'
            
            services.append({
                'name': expected['name'],
                'description': expected['description'],
                'status': status,
                'port': expected['port'],
                'connectivity': connectivity,
                'docker_status': 'unknown'
            })
    
    return services

def test_service_connectivity(service_config):
    """Test de connectivité pour un service - FONCTION CORRIGÉE"""
    try:
        # Détecter si on est dans un conteneur Docker
        import os
        in_docker = os.path.exists('/.dockerenv')
        
        if in_docker:
            # Dans Docker : utiliser les noms de services
            host = service_config['docker_host']
            port = service_config['port']
            test_url = f"http://{host}:{port}"
        else:
            # Hors Docker : utiliser localhost
            port = service_config['external_port']
            test_url = f"http://localhost:{port}"
        
        logger.debug(f"Test connectivité: {test_url}")
        
        # Test avec timeout court
        response = requests.get(test_url, timeout=3)
        
        if response.status_code < 500:
            return 'ok'
        else:
            return 'error'
            
    except requests.exceptions.ConnectionError:
        return 'unreachable'
    except requests.exceptions.Timeout:
        return 'timeout'
    except Exception as e:
        logger.warning(f"Erreur test connectivité {service_config['name']}: {e}")
        return 'error'



def get_storage_metrics():
    """Métriques de stockage"""
    try:
        storage_data = {
            'elasticsearch': get_elasticsearch_storage(),
            'graylog': get_graylog_storage(),
            'database': get_database_storage(),
            'docker_volumes': get_docker_volumes_storage()
        }
        return storage_data
    except Exception as e:
        logger.error(f"Erreur métriques stockage: {e}")
        return {'error': str(e)}


def get_elasticsearch_storage():
    """Stockage Elasticsearch - VERSION CORRIGÉE"""
    try:
        # Détecter l'environnement
        import os
        if os.path.exists('/.dockerenv'):
            # Dans Docker
            url = 'http://elasticsearch:9200/_cat/indices?format=json'
        else:
            # Hors Docker
            url = 'http://localhost:9200/_cat/indices?format=json'
        
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            indices = response.json()
            return {
                'indices_count': len(indices),
                'total_size': sum(int(idx.get('store.size', '0b').replace('kb', '').replace('mb', '').replace('gb', '').replace('b', '') or 0) for idx in indices),
                'status': 'ok'
            }
    except Exception as e:
        logger.debug(f"Erreur Elasticsearch storage: {e}")
    
    return {'status': 'unreachable'}


def get_graylog_storage():
    """Stockage Graylog - VERSION CORRIGÉE"""
    try:
        import os
        if os.path.exists('/.dockerenv'):
            # Dans Docker
            url = 'http://graylog:9000/api/count/total'
        else:
            # Hors Docker
            url = 'http://localhost:9000/api/count/total'
        
        response = requests.get(url, auth=('admin', 'admin'), timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'messages_count': data.get('events', 0),
                'status': 'ok'
            }
    except Exception as e:
        logger.debug(f"Erreur Graylog storage: {e}")
    
    return {'status': 'unreachable'}


def get_database_storage():
    """Métriques base de données"""
    try:
        stats = current_app.db.get_stats()
        return {
            'tables_count': len(stats.get('tables', [])),
            'status': 'ok'
        }
    except:
        return {'status': 'error'}

def get_docker_volumes_storage():
    """Stockage volumes Docker"""
    try:
        client = docker.from_env()
        volumes = client.volumes.list()
        toolbox_volumes = [v for v in volumes if 'toolbox' in v.name]
        return {
            'volumes_count': len(toolbox_volumes),
            'total_volumes': len(volumes),
            'status': 'ok'
        }
    except:
        return {'status': 'error'}


def get_recent_logs_stats():
    """Statistiques des logs récents - VERSION CORRIGÉE CONNECTIVITÉ"""
    logger.info("🔍 Récupération des statistiques de logs...")
    
    # Détecter l'environnement
    import os
    in_docker = os.path.exists('/.dockerenv')
    
    # MÉTHODE 1: Essayer via Elasticsearch
    try:
        if in_docker:
            es_base_url = 'http://elasticsearch:9200'
        else:
            es_base_url = 'http://localhost:9200'
        
        logger.info("📊 Tentative de connexion à Elasticsearch...")
        
        # Vérifier si Elasticsearch est accessible
        health_response = requests.get(f'{es_base_url}/_cluster/health', timeout=3)
        if health_response.status_code == 200:
            logger.info("✅ Elasticsearch accessible")
            
            # Chercher les index Graylog
            indices_response = requests.get(f'{es_base_url}/_cat/indices?format=json', timeout=3)
            if indices_response.status_code == 200:
                indices = indices_response.json()
                graylog_indices = [idx for idx in indices if 'graylog' in idx.get('index', '').lower()]
                
                if graylog_indices:
                    logger.info(f"📋 Trouvé {len(graylog_indices)} index Graylog")
                    
                    # Requête pour les statistiques détaillées
                    search_response = requests.get(
                        f'{es_base_url}/graylog_*/_search', 
                        json={
                            "size": 0,
                            "query": {
                                "range": {
                                    "@timestamp": {
                                        "gte": "now-24h"
                                    }
                                }
                            },
                            "aggs": {
                                "recent_logs": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "fixed_interval": "1h",
                                        "min_doc_count": 0
                                    }
                                },
                                "log_levels": {
                                    "terms": {
                                        "field": "level.keyword",
                                        "size": 10,
                                        "missing": "UNKNOWN"
                                    }
                                }
                            }
                        }, 
                        timeout=5
                    )
                    
                    if search_response.status_code == 200:
                        data = search_response.json()
                        total_hits = data.get('hits', {}).get('total', {})
                        
                        # Support pour différentes versions d'Elasticsearch
                        if isinstance(total_hits, dict):
                            total_count = total_hits.get('value', 0)
                        else:
                            total_count = total_hits or 0
                        
                        result = {
                            'total_hits': total_count,
                            'recent_activity': data.get('aggregations', {}).get('recent_logs', {}).get('buckets', []),
                            'log_levels': data.get('aggregations', {}).get('log_levels', {}).get('buckets', []),
                            'status': 'ok',
                            'source': 'elasticsearch'
                        }
                        
                        logger.info(f"✅ Stats Elasticsearch: {total_count} logs")
                        return result
    
    except Exception as e:
        logger.warning(f"⚠️ Erreur Elasticsearch: {e}")
    
    # MÉTHODE 2: Essayer via l'API Graylog directement
    try:
        if in_docker:
            graylog_base_url = 'http://graylog:9000'
        else:
            graylog_base_url = 'http://localhost:9000'
        
        logger.info("📊 Tentative de connexion à Graylog API...")
        
        # Test de connexion Graylog
        graylog_response = requests.get(
            f'{graylog_base_url}/api/system', 
            auth=('admin', 'admin'), 
            timeout=3
        )
        
        if graylog_response.status_code == 200:
            logger.info("✅ Graylog API accessible")
            
            # Récupérer le nombre total de messages via l'API Graylog
            count_response = requests.get(
                f'{graylog_base_url}/api/count/total', 
                auth=('admin', 'admin'), 
                timeout=5
            )
            
            if count_response.status_code == 200:
                count_data = count_response.json()
                total_messages = count_data.get('events', 0)
                
                result = {
                    'total_hits': total_messages,
                    'recent_activity': [],  # Pas de données d'activité détaillées
                    'log_levels': [],       # Pas de niveaux détaillés
                    'status': 'ok',
                    'source': 'graylog_api'
                }
                
                logger.info(f"✅ Stats Graylog API: {total_messages} messages")
                return result
    
    except Exception as e:
        logger.warning(f"⚠️ Erreur Graylog API: {e}")
    
    # AUCUN SERVICE ACCESSIBLE
    logger.warning("⚠️ Aucun service de logs accessible - Retour N/A")
    return {
        'total_hits': 0,
        'recent_activity': [],
        'log_levels': [],
        'status': 'unreachable',
        'source': 'none'
    }


def get_active_alerts():
    """Alertes actives du système"""
    alerts = []
    
    # Vérifier les métriques système
    try:
        if psutil.cpu_percent(interval=1) > 80:
            alerts.append({
                'type': 'warning',
                'message': 'CPU usage élevé (>80%)',
                'timestamp': datetime.now().isoformat()
            })
        
        if psutil.virtual_memory().percent > 85:
            alerts.append({
                'type': 'warning', 
                'message': 'Mémoire usage élevé (>85%)',
                'timestamp': datetime.now().isoformat()
            })
        
        if psutil.disk_usage('/').percent > 90:
            alerts.append({
                'type': 'critical',
                'message': 'Espace disque critique (>90%)',
                'timestamp': datetime.now().isoformat()
            })
    except:
        pass
    
    # Vérifier les services critiques
    services = get_services_status()
    critical_services = ['toolbox-app-huntkit', 'toolbox-graylog', 'toolbox-elasticsearch']
    
    for service in services:
        if service['name'] in critical_services and service['status'] != 'healthy':
            alerts.append({
                'type': 'critical',
                'message': f"Service critique hors ligne: {service['description']}",
                'timestamp': datetime.now().isoformat()
            })
    
    return alerts

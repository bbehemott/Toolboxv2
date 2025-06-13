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
    """Status des services Docker"""
    services = []
    
    # Services essentiels à surveiller
    expected_services = [
        {'name': 'toolbox-app-huntkit', 'port': 5000, 'description': 'Application principale'},
        {'name': 'toolbox-graylog', 'port': 9000, 'description': 'Centralisation logs'},
        {'name': 'toolbox-kibana', 'port': 5601, 'description': 'Exploration logs'},
        {'name': 'toolbox-elasticsearch', 'port': 9200, 'description': 'Moteur de recherche'},
        {'name': 'toolbox-postgres', 'port': 5432, 'description': 'Base de données'},
        {'name': 'toolbox-redis', 'port': 6379, 'description': 'Cache & broker'},
        {'name': 'toolbox-minio', 'port': 9090, 'description': 'Stockage sécurisé'},
        {'name': 'toolbox-worker-huntkit', 'port': None, 'description': 'Worker Celery'},
        {'name': 'toolbox-metricbeat', 'port': None, 'description': 'Collecte métriques'}
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
                    
                    # Test connectivité pour services avec port
                    connectivity = 'unknown'
                    if expected['port'] and container.status == 'running':
                        try:
                            response = requests.get(f"http://localhost:{expected['port']}", 
                                                  timeout=2)
                            connectivity = 'ok' if response.status_code < 500 else 'error'
                        except:
                            connectivity = 'unreachable'
                    
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
        # Fallback : test direct des ports
        for expected in expected_services:
            if expected['port']:
                try:
                    response = requests.get(f"http://localhost:{expected['port']}", timeout=2)
                    status = 'healthy' if response.status_code < 500 else 'unhealthy'
                    connectivity = 'ok'
                except:
                    status = 'unhealthy'
                    connectivity = 'unreachable'
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
    """Stockage Elasticsearch"""
    try:
        response = requests.get('http://localhost:9200/_cat/indices?format=json', timeout=5)
        if response.status_code == 200:
            indices = response.json()
            total_size = sum(int(idx.get('store.size', '0').replace('kb', '').replace('mb', '').replace('gb', '')) for idx in indices)
            return {
                'indices_count': len(indices),
                'total_size': total_size,
                'status': 'ok'
            }
    except:
        pass
    
    return {'status': 'unreachable'}

def get_graylog_storage():
    """Stockage Graylog"""
    try:
        response = requests.get('http://localhost:9000/api/count/total', 
                              auth=('admin', 'admin'), timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'messages_count': data.get('events', 0),
                'status': 'ok'
            }
    except:
        pass
    
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
    """Statistiques des logs récents"""
    try:
        # Stats depuis Elasticsearch
        response = requests.get('http://localhost:9200/graylog_*/_search', 
                              json={
                                  "size": 0,
                                  "aggs": {
                                      "recent_logs": {
                                          "date_histogram": {
                                              "field": "@timestamp",
                                              "interval": "1h"
                                          }
                                      },
                                      "log_levels": {
                                          "terms": {
                                              "field": "level",
                                              "size": 10
                                          }
                                      }
                                  }
                              }, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'total_hits': data.get('hits', {}).get('total', {}).get('value', 0),
                'recent_activity': data.get('aggregations', {}).get('recent_logs', {}).get('buckets', []),
                'log_levels': data.get('aggregations', {}).get('log_levels', {}).get('buckets', []),
                'status': 'ok'
            }
    except:
        pass
    
    return {'status': 'unreachable'}

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

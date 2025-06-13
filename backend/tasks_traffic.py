"""
Tâches Celery pour traffic analysis - S'intègre avec votre système existant
"""

from celery import current_app as celery_app
from database import DatabaseManager
from modules.traffic_analysis import TrafficAnalysisModule
from api.traffic_analysis import TrafficAnalysisModule
import os
import logging

logger = logging.getLogger('toolbox.traffic')

@celery_app.task(bind=True, name='tasks.traffic_pentest_capture')
def traffic_pentest_capture(self, target, duration=60, user_id=None):
    """
    Tâche 20 - Capture traffic pendant pentest
    S'intègre avec votre système de tâches existant
    """
    
    task_id = self.request.id
    
    try:
        # Mise à jour du statut (comme vos autres tâches)
        self.update_state(
            state='PROGRESS',
            meta={'status': f'Capture trafic {target}', 'progress': 10}
        )
        
        # Utiliser votre analyzer
        analyzer = TrafficAnalysisModule()
        result = analyzer.pentest_capture(target, duration)
        
        if result['success']:
            # Sauvegarder en BDD (comme vos autres résultats)
            db = DatabaseManager()
            db.save_traffic_result(
                task_id=task_id,
                user_id=user_id,
                task_type='pentest_capture',
                target=target,
                result_data=result,
                pcap_file=result.get('pcap_file')
            )
            
            self.update_state(
                state='SUCCESS',
                meta={
                    'status': 'Capture terminée',
                    'progress': 100,
                    'result': result
                }
            )
        else:
            raise Exception(result.get('error', 'Erreur capture'))
            
        return result
        
    except Exception as e:
        logger.error(f"Erreur tâche traffic capture: {e}")
        self.update_state(
            state='FAILURE',
            meta={'status': f'Erreur: {str(e)}', 'error': str(e)}
        )
        raise

@celery_app.task(bind=True, name='tasks.traffic_forensic_analysis')
def traffic_forensic_analysis(self, pcap_file_path, user_id=None):
    """
    Tâche 45 - Analyse forensique PCAP
    S'intègre avec votre système de tâches existant
    """
    
    task_id = self.request.id
    
    try:
        self.update_state(
            state='PROGRESS', 
            meta={'status': 'Analyse forensique en cours', 'progress': 20}
        )
        
        analyzer = TrafficAnalysisModule()
        result = analyzer.forensic_analysis(pcap_file_path)
        
        if result['success']:
            # Sauvegarder en BDD
            db = DatabaseManager()
            db.save_traffic_result(
                task_id=task_id,
                user_id=user_id,
                task_type='forensic_analysis',
                target=pcap_file_path,
                result_data=result
            )
            
            self.update_state(
                state='SUCCESS',
                meta={
                    'status': 'Analyse terminée',
                    'progress': 100,
                    'result': result
                }
            )
        else:
            raise Exception(result.get('error', 'Erreur analyse'))
            
        return result
        
    except Exception as e:
        logger.error(f"Erreur tâche forensic: {e}")
        self.update_state(
            state='FAILURE',
            meta={'status': f'Erreur: {str(e)}', 'error': str(e)}
        )
        raise

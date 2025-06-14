#!/usr/bin/env python3
"""
Script d'Auto-Configuration Kibana pour Dashboard Sécurité
Créé automatiquement les visualisations et dashboard
"""

import requests
import json
import time
import sys
from datetime import datetime

class KibanaAutoSetup:
    def __init__(self, kibana_url="http://localhost:5601"):
        self.base_url = kibana_url
        self.headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }
        self.index_pattern_id = None
        
    def wait_for_kibana(self, max_attempts=10):
        """Attendre que Kibana soit prêt"""
        print("🔄 Vérification de Kibana...")
        for i in range(max_attempts):
            try:
                response = requests.get(f"{self.base_url}/api/status", timeout=5)
                if response.status_code == 200:
                    print("✅ Kibana accessible !")
                    return True
            except:
                pass
            print(f"⏳ Attente Kibana... ({i+1}/{max_attempts})")
            time.sleep(10)
        
        print("❌ Kibana non accessible")
        return False
    
    def create_index_pattern(self):
        """Créer ou vérifier l'index pattern graylog_*"""
        print("\n📋 Configuration Index Pattern...")
        
        # Vérifier si l'index pattern existe déjà
        try:
            response = requests.get(
                f"{self.base_url}/api/saved_objects/_find?type=index-pattern&search_fields=title&search=graylog*",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('total', 0) > 0:
                    self.index_pattern_id = data['saved_objects'][0]['id']
                    print(f"✅ Index pattern existant trouvé: {self.index_pattern_id}")
                    return True
        except Exception as e:
            print(f"⚠️ Erreur vérification index pattern: {e}")
        
        # Créer un nouveau index pattern
        index_pattern_config = {
            "attributes": {
                "title": "graylog_*",
                "timeFieldName": "@timestamp"
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/saved_objects/index-pattern",
                headers=self.headers,
                json=index_pattern_config
            )
            
            if response.status_code in [200, 201]:
                self.index_pattern_id = response.json()['id']
                print(f"✅ Index pattern créé: {self.index_pattern_id}")
                return True
            else:
                print(f"❌ Erreur création index pattern: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Erreur création index pattern: {e}")
            return False
    
    def create_security_timeline_viz(self):
        """Créer la visualisation Timeline des Menaces"""
        print("\n📈 Création Timeline des Menaces...")
        
        viz_config = {
            "attributes": {
                "title": "Security Threats Timeline",
                "visState": json.dumps({
                    "title": "Security Threats Timeline",
                    "type": "line",
                    "params": {
                        "grid": {"categoryLines": False, "style": {"color": "#eee"}},
                        "categoryAxes": [{
                            "id": "CategoryAxis-1",
                            "type": "category",
                            "position": "bottom",
                            "show": True,
                            "style": {},
                            "scale": {"type": "linear"},
                            "labels": {"show": True, "truncate": 100},
                            "title": {}
                        }],
                        "valueAxes": [{
                            "id": "ValueAxis-1",
                            "name": "LeftAxis-1",
                            "type": "value",
                            "position": "left",
                            "show": True,
                            "style": {},
                            "scale": {"type": "linear", "mode": "normal"},
                            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                            "title": {"text": "Nombre de menaces"}
                        }],
                        "seriesParams": [{
                            "show": "true",
                            "type": "line",
                            "mode": "normal",
                            "data": {"label": "Menaces", "id": "1"},
                            "valueAxis": "ValueAxis-1",
                            "drawLinesBetweenPoints": True,
                            "showCircles": True
                        }],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "times": [],
                        "addTimeMarker": False
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "date_histogram",
                            "schema": "segment",
                            "params": {
                                "field": "@timestamp",
                                "interval": "1h",
                                "customInterval": "2h",
                                "min_doc_count": 1,
                                "extended_bounds": {}
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Timeline des menaces de sécurité détectées",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern_id,
                        "query": {
                            "match": {
                                "message": {
                                    "query": "brute force attack scan injection",
                                    "type": "phrase"
                                }
                            }
                        },
                        "filter": []
                    })
                }
            }
        }
        
        return self._create_visualization("security-timeline", viz_config)
    
    def create_top_ips_viz(self):
        """Créer la visualisation Top IPs Malveillantes"""
        print("\n🎯 Création Top IPs Malveillantes...")
        
        viz_config = {
            "attributes": {
                "title": "Top Malicious IPs",
                "visState": json.dumps({
                    "title": "Top Malicious IPs",
                    "type": "table",
                    "params": {
                        "perPage": 10,
                        "showPartialRows": False,
                        "showMeticsAtAllLevels": False,
                        "sort": {"columnIndex": None, "direction": None},
                        "showTotal": False,
                        "totalFunc": "sum"
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "terms",
                            "schema": "bucket",
                            "params": {
                                "field": "source_ip.keyword",
                                "size": 10,
                                "order": "desc",
                                "orderBy": "1"
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Top 10 des IPs sources malveillantes",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern_id,
                        "query": {
                            "query_string": {
                                "query": "source_ip:* AND (message:*attack* OR message:*brute* OR message:*scan*)",
                                "analyze_wildcard": True
                            }
                        },
                        "filter": []
                    })
                }
            }
        }
        
        return self._create_visualization("top-malicious-ips", viz_config)
    
    def create_attack_types_pie(self):
        """Créer le pie chart des types d'attaques"""
        print("\n🥧 Création Répartition Types d'Attaques...")
        
        viz_config = {
            "attributes": {
                "title": "Attack Types Distribution",
                "visState": json.dumps({
                    "title": "Attack Types Distribution", 
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "isDonut": True
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "filters",
                            "schema": "segment",
                            "params": {
                                "filters": [
                                    {
                                        "input": {"query": {"query_string": {"query": "message:*brute*", "analyze_wildcard": True}}},
                                        "label": "Brute Force"
                                    },
                                    {
                                        "input": {"query": {"query_string": {"query": "message:*scan*", "analyze_wildcard": True}}},
                                        "label": "Port Scan"
                                    },
                                    {
                                        "input": {"query": {"query_string": {"query": "message:*injection* OR message:*xss*", "analyze_wildcard": True}}},
                                        "label": "Web Attack"
                                    },
                                    {
                                        "input": {"query": {"query_string": {"query": "message:*access*", "analyze_wildcard": True}}},
                                        "label": "Unauthorized Access"
                                    }
                                ]
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Répartition des types d'attaques détectées",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern_id,
                        "query": {"match_all": {}},
                        "filter": []
                    })
                }
            }
        }
        
        return self._create_visualization("attack-types-pie", viz_config)
    
    def create_security_heatmap(self):
        """Créer la heatmap sécurité"""
        print("\n🌡️ Création Heatmap Sécurité...")
        
        viz_config = {
            "attributes": {
                "title": "Security Activity Heatmap",
                "visState": json.dumps({
                    "title": "Security Activity Heatmap",
                    "type": "heatmap",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "enableHover": False,
                        "legendPosition": "right",
                        "times": [],
                        "colorsNumber": 4,
                        "colorSchema": "Red to Yellow",
                        "setColorRange": False,
                        "colorsRange": [],
                        "invertColors": False,
                        "percentageMode": False,
                        "valueAxes": [{
                            "show": False,
                            "id": "ValueAxis-1",
                            "type": "value",
                            "scale": {"type": "linear", "defaultYExtents": False},
                            "labels": {"show": False, "rotate": 0, "color": "#555"}
                        }]
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "date_histogram",
                            "schema": "segment",
                            "params": {
                                "field": "@timestamp",
                                "interval": "3h",
                                "customInterval": "2h",
                                "min_doc_count": 1,
                                "extended_bounds": {}
                            }
                        },
                        {
                            "id": "3",
                            "enabled": True,
                            "type": "terms",
                            "schema": "group",
                            "params": {
                                "field": "level",
                                "size": 5,
                                "order": "desc",
                                "orderBy": "1"
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Heatmap de l'activité de sécurité par niveau et temps",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern_id,
                        "query": {"match_all": {}},
                        "filter": []
                    })
                }
            }
        }
        
        return self._create_visualization("security-heatmap", viz_config)
    
    def create_security_dashboard(self, viz_ids):
        """Créer le dashboard principal"""
        print("\n🛡️ Création Dashboard Sécurité...")
        
        # Configuration des panels du dashboard
        panels = [
            {
                "version": "7.10.2",
                "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "1"},
                "panelIndex": "1",
                "embeddableConfig": {},
                "panelRefName": "panel_1"
            },
            {
                "version": "7.10.2", 
                "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "2"},
                "panelIndex": "2",
                "embeddableConfig": {},
                "panelRefName": "panel_2"
            },
            {
                "version": "7.10.2",
                "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "3"}, 
                "panelIndex": "3",
                "embeddableConfig": {},
                "panelRefName": "panel_3"
            },
            {
                "version": "7.10.2",
                "gridData": {"x": 0, "y": 30, "w": 48, "h": 15, "i": "4"},
                "panelIndex": "4", 
                "embeddableConfig": {},
                "panelRefName": "panel_4"
            }
        ]
        
        # Références aux visualisations
        references = [
            {"name": "panel_1", "type": "visualization", "id": viz_ids.get("timeline", "")},
            {"name": "panel_2", "type": "visualization", "id": viz_ids.get("top_ips", "")},
            {"name": "panel_3", "type": "visualization", "id": viz_ids.get("attack_types", "")},
            {"name": "panel_4", "type": "visualization", "id": viz_ids.get("heatmap", "")}
        ]
        
        dashboard_config = {
            "attributes": {
                "title": "Security Operations Dashboard",
                "hits": 0,
                "description": "Dashboard de sécurité - Tâches 24 & 25",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps({
                    "useMargins": True,
                    "syncColors": False,
                    "hidePanelTitles": False
                }),
                "version": 1,
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": references
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/saved_objects/dashboard",
                headers=self.headers,
                json=dashboard_config
            )
            
            if response.status_code in [200, 201]:
                dashboard_id = response.json()['id']
                print(f"✅ Dashboard créé: {dashboard_id}")
                return dashboard_id
            else:
                print(f"❌ Erreur création dashboard: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Erreur création dashboard: {e}")
            return None
    
    def _create_visualization(self, viz_id, config):
        """Créer une visualisation générique"""
        try:
            response = requests.post(
                f"{self.base_url}/api/saved_objects/visualization/{viz_id}",
                headers=self.headers,
                json=config
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Visualisation créée: {viz_id}")
                return viz_id
            elif response.status_code == 409:
                print(f"⚠️ Visualisation existe déjà: {viz_id}")
                return viz_id
            else:
                print(f"❌ Erreur création {viz_id}: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Erreur création {viz_id}: {e}")
            return None
    
    def setup_complete_dashboard(self):
        """Configuration complète du dashboard"""
        print("🚀 CONFIGURATION COMPLÈTE KIBANA DASHBOARD")
        print("=" * 50)
        
        # Vérifier Kibana
        if not self.wait_for_kibana():
            return False
        
        # Créer/vérifier index pattern
        if not self.create_index_pattern():
            return False
        
        # Créer les visualisations
        viz_ids = {}
        viz_ids['timeline'] = self.create_security_timeline_viz()
        viz_ids['top_ips'] = self.create_top_ips_viz()
        viz_ids['attack_types'] = self.create_attack_types_pie()
        viz_ids['heatmap'] = self.create_security_heatmap()
        
        # Créer le dashboard
        dashboard_id = self.create_security_dashboard(viz_ids)
        
        if dashboard_id:
            print(f"\n🎉 CONFIGURATION TERMINÉE !")
            print(f"Dashboard URL: {self.base_url}/app/kibana#/dashboard/{dashboard_id}")
            print(f"Ou aller dans: Dashboard → Security Operations Dashboard")
            return True
        else:
            print("\n❌ Erreur configuration dashboard")
            return False

def main():
    """Fonction principale"""
    print("🛡️ AUTO-SETUP KIBANA DASHBOARD SÉCURITÉ")
    print("Tâches 24 & 25 - Détection d'Intrusion & Pare-feu")
    print("")
    
    # Initialiser le setup
    setup = KibanaAutoSetup()
    
    # Lancer la configuration
    success = setup.setup_complete_dashboard()
    
    if success:
        print("\n🎯 PROCHAINES ÉTAPES:")
        print("1. Ouvrir Kibana: http://localhost:5601")
        print("2. Aller dans Dashboard → Security Operations Dashboard")
        print("3. Définir période: Last 24 hours ou Last 7 days")
        print("4. Activer auto-refresh: 30 seconds")
        print("\n✅ Votre dashboard de sécurité est prêt !")
    else:
        print("\n❌ Configuration échouée")
        print("Vérifiez que Kibana est accessible sur http://localhost:5601")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

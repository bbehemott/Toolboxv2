# =============================================================================
# GÉNÉRATEUR DE RAPPORTS AMÉLIORÉS
# =============================================================================

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from jinja2 import Template
import json
from datetime import datetime
import os

class ImprovedReportExporter:
    """Générateur de rapports de tâches améliorés"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Créer des styles personnalisés pour les PDF"""
        
        # Style pour les titres
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=20,
            textColor=HexColor('#2c3e50'),
            alignment=1  # Centré
        ))
        
        # Style pour les sous-titres
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'], 
            fontSize=14,
            spaceAfter=12,
            textColor=HexColor('#34495e'),
            borderWidth=1,
            borderColor=HexColor('#bdc3c7'),
            borderPadding=5
        ))
        
        # Style pour le contenu normal
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            leftIndent=10
        ))

    def generate_discovery_report(self, task_data, format='both'):
        """Générer rapport de découverte réseau amélioré"""
        
        report_data = {
            'task_id': task_data.get('task_id', 'N/A'),
            'timestamp': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'target': task_data.get('target', 'N/A'),
            'scan_type': task_data.get('scan_type', 'Découverte réseau'),
            'duration': task_data.get('duration', '< 1 minute'),
            'hosts_found': task_data.get('hosts_found', []),
            'total_hosts': len(task_data.get('hosts_found', [])),
            'services': task_data.get('services', []),
            'vulnerabilities': task_data.get('vulnerabilities', []),
            'raw_output': task_data.get('raw_output', '')
        }
        
        reports = {}
        
        if format in ['txt', 'both']:
            reports['txt_content'] = self.generate_txt_report(report_data)
        
        if format in ['pdf', 'both']:
            reports['pdf_path'] = self.generate_pdf_report(report_data)
        
        return reports


    def generate_txt_report(self, data):
        """Génération rapport texte adaptatif selon le type d'analyse"""
        
        # Déterminer le type d'analyse
        scan_type = data.get('scan_type', 'Analyse générale')
        
        # Template adaptatif selon le type
        if 'web_audit' in scan_type or 'audit_web' in scan_type:
            template_str = self._get_web_audit_template()
        elif 'forensic' in scan_type or 'forensique' in scan_type:
            template_str = self._get_forensic_template()
        elif 'brute_force' in scan_type or 'force_brute' in scan_type:
            template_str = self._get_brute_force_template()
        else:
            template_str = self._get_discovery_template()
        
        from jinja2 import Template
        template = Template(template_str)
        return template.render(**data)
    
    def _get_web_audit_template(self):
        """Template pour audit web"""
        return """╔══════════════════════════════════════════════════════════════════╗
    ║                      RAPPORT D'AUDIT WEB                        ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    📋 INFORMATIONS GÉNÉRALES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • ID de tâche    : {{ task_id }}
      • Date/Heure     : {{ timestamp }}
      • Cible          : {{ target }}
      • Type d'audit   : {{ scan_type }}
      • Durée          : {{ duration }}
    
    📊 RÉSUMÉ EXÉCUTIF
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • Applications web analysées : {{ total_hosts }}
      • Services web identifiés    : {{ services|length }}
      • Vulnérabilités détectées   : {{ vulnerabilities|length }}
    
    {% if hosts_found %}
    🌐 APPLICATIONS WEB ANALYSÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for host in hosts_found %}
    ┌─ {{ host.ip or host.address }}
    ├─ État         : {{ host.status }}
    ├─ Type         : {{ host.os or 'Application Web' }}
    └─ Ports web    : {{ host.open_ports|join(', ') if host.open_ports else 'HTTP/HTTPS' }}
    
    {% endfor %}
    {% endif %}
    
    {% if services %}
    🔧 SERVICES WEB IDENTIFIÉS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for service in services %}
    ┌─ {{ service.name }} (Port {{ service.port }})
    ├─ Version      : {{ service.version or 'Non identifiée' }}
    ├─ Protocole    : {{ service.protocol }}
    ├─ État         : {{ service.state }}
    └─ Serveur      : {{ service.host }}
    
    {% endfor %}
    {% endif %}
    
    {% if vulnerabilities %}
    🚨 VULNÉRABILITÉS WEB DÉTECTÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for vuln in vulnerabilities %}
    ┌─ {{ vuln.title }}
    ├─ Criticité    : {{ vuln.severity }}
    ├─ Source       : {{ vuln.source or 'Scanner Web' }}
    ├─ Port affecté : {{ vuln.port }}
    ├─ Serveur      : {{ vuln.host }}
    └─ Description  : {{ vuln.description }}
    
    {% endfor %}
    {% else %}
    🚨 VULNÉRABILITÉS WEB DÉTECTÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✅ Aucune vulnérabilité web critique détectée
    {% endif %}
    
    🛡️ RECOMMANDATIONS WEB
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% if vulnerabilities %}
    - Corriger en priorité les vulnérabilités critiques et élevées
    - Mettre à jour les composants web avec des versions obsolètes
    - Implémenter des mécanismes de protection (WAF, CSP)
    - Auditer les configurations des serveurs web
    {% else %}
    - Bonne configuration de sécurité détectée
    - Maintenir les bonnes pratiques actuelles
    - Effectuer des audits réguliers pour détecter de nouvelles vulnérabilités
    {% endif %}
    
    {% if raw_output %}
    💻 DÉTAILS TECHNIQUES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {{ raw_output }}
    {% endif %}
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Audit web généré par la Toolbox Cybersécurité - {{ timestamp }}
    """
    
    def _get_forensic_template(self):
        """Template pour analyse forensique"""
        return """╔══════════════════════════════════════════════════════════════════╗
    ║                   RAPPORT D'ANALYSE FORENSIQUE                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    📋 INFORMATIONS GÉNÉRALES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • ID de tâche    : {{ task_id }}
      • Date/Heure     : {{ timestamp }}
      • Échantillon    : {{ target }}
      • Type d'analyse : {{ scan_type }}
      • Durée          : {{ duration }}
    
    📊 RÉSUMÉ EXÉCUTIF
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • Artefacts analysés         : {{ total_hosts }}
      • Éléments identifiés        : {{ services|length }}
      • Anomalies/Menaces détectées: {{ vulnerabilities|length }}
    
    {% if hosts_found %}
    🔍 ARTEFACTS ANALYSÉS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for host in hosts_found %}
    ┌─ {{ host.ip or host.address }}
    ├─ État         : {{ host.status }}
    ├─ Type         : {{ host.os or 'Artefact numérique' }}
    └─ Éléments     : {{ host.open_ports|length if host.open_ports else 0 }} éléments détectés
    
    {% endfor %}
    {% endif %}
    
    {% if services %}
    🔧 ÉLÉMENTS IDENTIFIÉS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for service in services %}
    ┌─ {{ service.name }}
    ├─ Détails      : {{ service.version or 'Information non disponible' }}
    ├─ Type         : {{ service.protocol }}
    ├─ État         : {{ service.state }}
    └─ Source       : {{ service.host }}
    
    {% endfor %}
    {% endif %}
    
    {% if vulnerabilities %}
    ⚠️ ANOMALIES ET MENACES DÉTECTÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for vuln in vulnerabilities %}
    ┌─ {{ vuln.title }}
    ├─ Criticité    : {{ vuln.severity }}
    ├─ Source       : {{ vuln.source or 'Analyse Forensique' }}
    ├─ Référence    : {{ vuln.port if vuln.port != 'N/A' else 'Système' }}
    ├─ Emplacement  : {{ vuln.host }}
    └─ Description  : {{ vuln.description }}
    
    {% endfor %}
    {% else %}
    ⚠️ ANOMALIES ET MENACES DÉTECTÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✅ Aucune menace critique détectée dans l'analyse
    {% endif %}
    
    🛡️ RECOMMANDATIONS FORENSIQUES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% if vulnerabilities %}
    - Analyser en priorité les menaces critiques identifiées
    - Isoler les systèmes compromis si nécessaire
    - Collecter des preuves supplémentaires pour investigation
    - Documenter la chaîne de possession des preuves
    {% else %}
    - L'analyse n'a révélé aucune menace immédiate
    - Conserver les artefacts pour référence future
    - Poursuivre l'investigation si d'autres indices apparaissent
    {% endif %}
    
    {% if raw_output %}
    💻 DONNÉES TECHNIQUES DÉTAILLÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {{ raw_output }}
    {% endif %}
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Analyse forensique générée par la Toolbox Cybersécurité - {{ timestamp }}
    """
    
    def _get_brute_force_template(self):
        """Template pour force brute"""
        return """╔══════════════════════════════════════════════════════════════════╗
    ║                    RAPPORT DE FORCE BRUTE                       ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    📋 INFORMATIONS GÉNÉRALES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • ID de tâche    : {{ task_id }}
      • Date/Heure     : {{ timestamp }}
      • Cible          : {{ target }}
      • Type d'attaque : {{ scan_type }}
      • Durée          : {{ duration }}
    
    📊 RÉSUMÉ EXÉCUTIF
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • Systèmes testés            : {{ total_hosts }}
      • Services analysés          : {{ services|length }}
      • Credentials découverts     : {{ vulnerabilities|selectattr('severity', 'equalto', 'Critical')|list|length }}
    
    {% if hosts_found %}
    🎯 SYSTÈMES TESTÉS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for host in hosts_found %}
    ┌─ {{ host.ip or host.address }}
    ├─ État         : {{ host.status }}
    ├─ Système      : {{ host.os or 'Système testé' }}
    └─ Services     : {{ host.open_ports|join(', ') if host.open_ports else 'N/A' }}
    
    {% endfor %}
    {% endif %}
    
    {% if services %}
    🔧 SERVICES ANALYSÉS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for service in services %}
    ┌─ {{ service.name }} (Port {{ service.port }})
    ├─ État de test : {{ service.state }}
    ├─ Protocole    : {{ service.protocol }}
    ├─ Résultat     : {{ service.version or 'Test effectué' }}
    └─ Système      : {{ service.host }}
    
    {% endfor %}
    {% endif %}
    
    {% if vulnerabilities %}
    🔓 CREDENTIALS ET FAILLES DÉCOUVERTES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for vuln in vulnerabilities %}
    ┌─ {{ vuln.title }}
    ├─ Criticité    : {{ vuln.severity }}
    {% if vuln.severity == 'Critical' %}├─ ⚠️ ACCÈS    : Credentials faibles détectés{% endif %}
    ├─ Service      : Port {{ vuln.port }}
    ├─ Système      : {{ vuln.host }}
    └─ Détails      : {{ vuln.description }}
    
    {% endfor %}
    {% else %}
    🔓 CREDENTIALS ET FAILLES DÉCOUVERTES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✅ Aucun credential faible détecté - Services résistants aux attaques
    {% endif %}
    
    🛡️ RECOMMANDATIONS SÉCURITÉ
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% set critical_vulns = vulnerabilities|selectattr('severity', 'equalto', 'Critical')|list %}
    {% if critical_vulns %}
    - 🚨 URGENT: Changer immédiatement les mots de passe faibles découverts
    - Implémenter une politique de mots de passe robuste
    - Activer l'authentification multi-facteurs (2FA/MFA)
    - Surveiller les tentatives de connexion suspectes
    - Considérer le blocage IP après échecs multiples
    {% else %}
    - Excellente résistance aux attaques par force brute
    - Maintenir les politiques de sécurité actuelles
    - Effectuer des tests réguliers pour vérifier la robustesse
    - Sensibiliser les utilisateurs aux bonnes pratiques
    {% endif %}
    
    {% if raw_output %}
    💻 DÉTAILS TECHNIQUES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {{ raw_output }}
    {% endif %}
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Test de force brute généré par la Toolbox Cybersécurité - {{ timestamp }}
    """
    
    def _get_discovery_template(self):
        """Template pour découverte réseau (existant)"""
        return """╔══════════════════════════════════════════════════════════════════╗
    ║                    RAPPORT DE DÉCOUVERTE RÉSEAU                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    📋 INFORMATIONS GÉNÉRALES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • ID de tâche    : {{ task_id }}
      • Date/Heure     : {{ timestamp }}
      • Cible          : {{ target }}
      • Type de scan   : {{ scan_type }}
      • Durée          : {{ duration }}
    
    📊 RÉSUMÉ EXÉCUTIF
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      • Hôtes découverts     : {{ total_hosts }}
      • Services identifiés  : {{ services|length }}
      • Vulnérabilités       : {{ vulnerabilities|length }}
    
    {% if hosts_found %}
    🖥️  HÔTES DÉCOUVERTS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for host in hosts_found %}
    ┌─ {{ host.ip or host.address }}
    ├─ État         : {{ host.status }}
    {% if host.hostname %}├─ Nom d'hôte   : {{ host.hostname }}{% endif %}
    ├─ OS détecté   : {{ host.os or 'Non identifié' }}
    └─ Ports ouverts: {{ host.open_ports|join(', ') if host.open_ports else 'Aucun' }}
    
    {% endfor %}
    {% endif %}
    
    {% if services %}
    🔧 SERVICES IDENTIFIÉS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for service in services %}
    ┌─ {{ service.name }} (Port {{ service.port }})
    ├─ Version      : {{ service.version or 'Non identifiée' }}
    ├─ Protocole    : {{ service.protocol }}
    ├─ État         : {{ service.state }}
    └─ Hôte         : {{ service.host }}
    
    {% endfor %}
    {% endif %}
    
    {% if vulnerabilities %}
    🚨 VULNÉRABILITÉS DÉTECTÉES
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% for vuln in vulnerabilities %}
    ┌─ {{ vuln.title }}
    ├─ Criticité    : {{ vuln.severity }}
    ├─ CVE          : {{ vuln.cve or 'N/A' }}
    ├─ Port affecté : {{ vuln.port }}
    ├─ Hôte         : {{ vuln.host }}
    └─ Description  : {{ vuln.description }}
    
    {% endfor %}
    {% endif %}
    
    🛡️  RECOMMANDATIONS
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {% if vulnerabilities %}
    - Traiter en priorité les vulnérabilités critiques
    - Mettre à jour les services identifiés avec des versions obsolètes
    - Vérifier la configuration des pare-feu
    {% else %}
    - Aucune vulnérabilité critique détectée
    - Maintenir les pratiques de sécurité actuelles
    {% endif %}
    - Effectuer des scans réguliers pour maintenir la visibilité
    
    {% if raw_output %}
    💻 SORTIE BRUTE
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {{ raw_output }}
    {% endif %}
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Rapport généré par la Toolbox Cybersécurité - {{ timestamp }}
    """


    def generate_pdf_report(self, data):
        """Génération rapport PDF professionnel"""
        
        filename = f"rapport-task-{data['task_id']}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = f"/tmp/{filename}"
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=1*inch)
        story = []
        
        # Titre principal
        story.append(Paragraph("RAPPORT DE TÂCHE CYBERSÉCURITÉ", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Informations générales
        story.append(Paragraph("📋 Informations Générales", self.styles['CustomHeading']))
        
        info_data = [
            ['ID de tâche', str(data['task_id'])],
            ['Date/Heure', data['timestamp']],
            ['Cible', str(data['target'])],
            ['Type de scan', data['scan_type']],
            ['Durée', data['duration']]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Résumé exécutif
        story.append(Paragraph("📊 Résumé Exécutif", self.styles['CustomHeading']))
        
        summary_data = [
            ['Hôtes découverts', str(data['total_hosts'])],
            ['Services identifiés', str(len(data['services']))],
            ['Vulnérabilités', str(len(data['vulnerabilities']))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('BACKGROUND', (1, 0), (1, -1), HexColor('#ecf0f1')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#2980b9'))
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Générer le PDF
        doc.build(story)
        return f"/api/download-pdf/{filename}"

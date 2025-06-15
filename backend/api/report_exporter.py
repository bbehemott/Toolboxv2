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
        """Génération rapport PDF professionnel - VERSION COMPLÈTE OPTIMALE"""
        try:
            # Générer un nom de fichier unique
            import uuid
            from datetime import datetime
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_id = str(uuid.uuid4())[:8]
            filename = f"rapport-task-{data['task_id']}-{timestamp}-{unique_id}.pdf"
            
            # Créer le répertoire /tmp s'il n'existe pas
            os.makedirs("/tmp", exist_ok=True)
            filepath = f"/tmp/{filename}"
            
            # Import des bibliothèques ReportLab
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.lib.colors import HexColor
            import logging
            
            logger = logging.getLogger('toolbox.report')
            logger.info(f"🔄 Génération PDF: {filepath}")
            
            # Créer le document PDF
            doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=1*inch)
            story = []
            
            # Styles personnalisés
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                alignment=1,  # Centre
                textColor=HexColor('#2c3e50')
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=12,
                textColor=HexColor('#3498db')
            )
            
            subheading_style = ParagraphStyle(
                'CustomSubHeading',
                parent=styles['Heading3'],
                fontSize=12,
                spaceAfter=8,
                textColor=HexColor('#2c3e50')
            )
            
            # Titre principal
            story.append(Paragraph("🛡️ RAPPORT DE DÉCOUVERTE CYBERSÉCURITÉ", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Informations générales
            story.append(Paragraph("📋 Informations Générales", heading_style))
            
            info_data = [
                ['ID de tâche', str(data.get('task_id', 'N/A'))],
                ['Date/Heure', data.get('timestamp', 'N/A')],
                ['Cible', str(data.get('target', 'N/A'))],
                ['Type de scan', data.get('scan_type', 'Découverte réseau')],
                ['Durée', data.get('duration', 'N/A')]
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
            story.append(Paragraph("📊 Résumé Exécutif", heading_style))
            
            summary_data = [
                ['Hôtes découverts', str(data.get('total_hosts', 0))],
                ['Services identifiés', str(len(data.get('services', [])))],
                ['Vulnérabilités', str(len(data.get('vulnerabilities', [])))]
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
            
            # ===== SOLUTION OPTIMALE : DÉTAILS COMPLETS DES HÔTES =====
            if data.get('hosts_found'):
                story.append(Paragraph("🖥️ Hôtes Découverts - Analyse Détaillée", heading_style))
                
                for i, host in enumerate(data['hosts_found'][:10]):
                    ip = host.get('ip', host.get('address', 'N/A'))
                    status = host.get('status', 'Unknown')
                    os_info = host.get('os', 'Non identifié')
                    hostname = host.get('hostname', '')
                    ports = host.get('open_ports', [])
                    
                    # Titre pour chaque hôte
                    host_title = f"Hôte {i+1}: {ip}"
                    if hostname:
                        host_title += f" ({hostname})"
                    story.append(Paragraph(host_title, subheading_style))
                    
                    # Informations de base
                    basic_info = [
                        ['État', status],
                        ['OS Détecté', os_info],
                        ['Nombre de ports ouverts', str(len(ports)) if ports else '0']
                    ]
                    
                    basic_table = Table(basic_info, colWidths=[2*inch, 4*inch])
                    basic_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), HexColor('#ecf0f1')),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4)
                    ]))
                    
                    story.append(basic_table)
                    story.append(Spacer(1, 0.1*inch))
                    
                    # AFFICHAGE COMPLET DE TOUS LES PORTS
                    if ports and len(ports) > 0:
                        story.append(Paragraph("<b>Ports ouverts détectés:</b>", styles['Normal']))
                        
                        # Trier les ports
                        sorted_ports = sorted(ports)
                        
                        # Catégorisation des ports
                        well_known_ports = {
                            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
                            995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL',
                            3389: 'RDP', 139: 'NetBIOS', 445: 'SMB', 161: 'SNMP', 389: 'LDAP',
                            636: 'LDAPS', 1521: 'Oracle', 5900: 'VNC', 6000: 'X11', 8080: 'HTTP-Alt',
                            8443: 'HTTPS-Alt', 9090: 'WebSphere', 111: 'Portmapper', 135: 'RPC',
                            2049: 'NFS', 514: 'Shell', 513: 'Login', 512: 'Exec'
                        }
                        
                        # Séparer ports connus et inconnus
                        known_ports = [(p, well_known_ports[p]) for p in sorted_ports if p in well_known_ports]
                        unknown_ports = [p for p in sorted_ports if p not in well_known_ports]
                        
                        # Afficher les services standards
                        if known_ports:
                            story.append(Paragraph("<b>Services standards identifiés:</b>", styles['Normal']))
                            
                            # Créer tableau pour les services connus
                            services_data = [['Port', 'Service', 'Port', 'Service']]
                            for j in range(0, len(known_ports), 2):
                                row = []
                                # Premier port/service
                                port1, service1 = known_ports[j]
                                row.extend([str(port1), service1])
                                
                                # Deuxième port/service (si disponible)
                                if j + 1 < len(known_ports):
                                    port2, service2 = known_ports[j + 1]
                                    row.extend([str(port2), service2])
                                else:
                                    row.extend(['', ''])
                                
                                services_data.append(row)
                            
                            services_table = Table(services_data, colWidths=[0.7*inch, 1.3*inch, 0.7*inch, 1.3*inch])
                            services_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#27ae60')),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 9),
                                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                                ('TOPPADDING', (0, 0), (-1, -1), 3),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 3)
                            ]))
                            
                            story.append(services_table)
                            story.append(Spacer(1, 0.05*inch))
                        
                        # Afficher les autres ports
                        if unknown_ports:
                            story.append(Paragraph("<b>Autres ports ouverts:</b>", styles['Normal']))
                            
                            # Créer tableau multi-colonnes pour tous les autres ports
                            ports_per_column = 8
                            num_columns = min(6, (len(unknown_ports) + ports_per_column - 1) // ports_per_column)
                            
                            # Organiser les ports en colonnes
                            columns = []
                            for col in range(num_columns):
                                start_idx = col * ports_per_column
                                end_idx = min(start_idx + ports_per_column, len(unknown_ports))
                                if start_idx < len(unknown_ports):
                                    columns.append(unknown_ports[start_idx:end_idx])
                            
                            # Créer les données du tableau
                            max_rows = max(len(col) for col in columns) if columns else 0
                            ports_data = []
                            
                            for row in range(max_rows):
                                row_data = []
                                for col in columns:
                                    if row < len(col):
                                        row_data.append(str(col[row]))
                                    else:
                                        row_data.append('')
                                ports_data.append(row_data)
                            
                            if ports_data:
                                # Calculer largeur des colonnes
                                col_width = 6*inch / len(columns)
                                
                                ports_table = Table(ports_data, colWidths=[col_width] * len(columns))
                                ports_table.setStyle(TableStyle([
                                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                    ('FONTNAME', (0, 0), (-1, -1), 'Courier-Bold'),
                                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#ddd')),
                                    ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
                                    ('LEFTPADDING', (0, 0), (-1, -1), 3),
                                    ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                                    ('BOTTOMPADDING', (0, 0), (-1, -1), 2)
                                ]))
                                
                                story.append(ports_table)
                        
                        # Résumé total des ports pour cet hôte
                        total_summary = f"<b>Total: {len(sorted_ports)} ports ouverts</b> "
                        if known_ports:
                            total_summary += f"({len(known_ports)} services identifiés, {len(unknown_ports)} autres ports)"
                        story.append(Paragraph(total_summary, styles['Normal']))
                        
                    else:
                        story.append(Paragraph("Aucun port ouvert détecté", styles['Normal']))
                    
                    story.append(Spacer(1, 0.2*inch))
            
            # Services identifiés (section séparée si des données services sont disponibles)
            if data.get('services'):
                story.append(Paragraph("🔧 Services Identifiés par Scan", heading_style))
                
                services_data = [['Service', 'Port', 'Version', 'Hôte']]
                for service in data['services'][:20]:  # Limiter à 20 services détaillés
                    name = service.get('name', 'N/A')
                    port = str(service.get('port', 'N/A'))
                    version = service.get('version', 'Non identifiée')
                    host = service.get('host', 'N/A')
                    
                    # Limiter la longueur pour éviter le débordement
                    name_display = name[:20] + "..." if len(name) > 20 else name
                    version_display = version[:30] + "..." if len(version) > 30 else version
                    host_display = host[:25] + "..." if len(host) > 25 else host
                    
                    services_data.append([name_display, port, version_display, host_display])
                
                services_table = Table(services_data, colWidths=[1.3*inch, 0.7*inch, 2.2*inch, 1.8*inch])
                services_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#27ae60')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f8f9fa')]),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
                ]))
                
                story.append(services_table)
                story.append(Spacer(1, 0.2*inch))
            
            # Vulnérabilités détectées
            if data.get('vulnerabilities'):
                story.append(Paragraph("🚨 Vulnérabilités Détectées", heading_style))
                
                vulns_data = [['Titre', 'Criticité', 'CVE', 'Hôte']]
                for vuln in data['vulnerabilities'][:15]:
                    title = vuln.get('title', 'N/A')
                    severity = vuln.get('severity', 'N/A')
                    cve = vuln.get('cve', 'N/A')
                    host = vuln.get('host', 'N/A')
                    
                    title_display = title[:40] + "..." if len(title) > 40 else title
                    cve_display = cve[:15] + "..." if len(cve) > 15 else cve
                    host_display = host[:20] + "..." if len(host) > 20 else host
                    
                    vulns_data.append([title_display, severity, cve_display, host_display])
                
                vulns_table = Table(vulns_data, colWidths=[2.7*inch, 0.8*inch, 1.2*inch, 1.3*inch])
                vulns_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e74c3c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f8f9fa')]),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
                ]))
                
                story.append(vulns_table)
                story.append(Spacer(1, 0.2*inch))
            
            # Recommandations
            story.append(Paragraph("🛡️ Recommandations", heading_style))
            recommendations = [
                "• Effectuer des scans réguliers pour maintenir la visibilité sur l'infrastructure",
                "• Vérifier la configuration des pare-feu et fermer les ports non nécessaires",
                "• Surveiller les services exposés et maintenir leurs versions à jour",
                "• Implémenter une surveillance continue des nouveaux hôtes et services"
            ]
            
            if data.get('vulnerabilities'):
                recommendations.insert(0, "• Traiter en priorité les vulnérabilités critiques et à haut risque détectées")
            
            for rec in recommendations:
                story.append(Paragraph(rec, styles['Normal']))
            
            # Pied de page
            story.append(Spacer(1, 0.5*inch))
            footer_text = f"Rapport généré par la Toolbox Cybersécurité - {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            story.append(Paragraph(footer_text, styles['Normal']))
            
            # Générer le PDF
            doc.build(story)
            
            logger.info(f"✅ PDF généré avec succès: {filepath}")
            logger.info(f"📏 Taille du fichier: {os.path.getsize(filepath)} bytes")
            
            # Retourner le chemin pour téléchargement
            return f"/tasks/api/download-pdf/{filename}"
            
        except Exception as e:
            logger.error(f"❌ Erreur génération PDF: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise e

# Dockerfile - Toolbox avec outils de pentest
FROM python:3.10-slim

# Métadonnées
LABEL maintainer="Toolbox Team"
LABEL version="2.1"
LABEL description="Toolbox Cybersécurité - Avec outils de pentest intégrés"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# ===== INSTALLATION DES OUTILS DE PENTEST =====
RUN apt-get update && apt-get install -y \
    # Outils de base
    curl \
    wget \
    git \
    build-essential \
    ca-certificates \
    procps \
    unzip \
    \
    # Outils de réseau
    nmap \
    masscan \
    netcat-traditional \
    dnsutils \
    \
    # Outils de bruteforce
    hydra \
    medusa \
    \
    # Dépendances Python
    libpq-dev \
    python3-dev \
    \
    # Dépendances pour certains outils
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ===== INSTALLATION DE NUCLEI =====
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei_3.1.0_linux_amd64.zip \
    && nuclei -version

# ===== INSTALLATION DE SQLMAP =====
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# ===== INSTALLATION DE GOBUSTER =====
RUN wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    && tar -xzf gobuster_Linux_x86_64.tar.gz \
    && mv gobuster /usr/local/bin/ \
    && chmod +x /usr/local/bin/gobuster \
    && rm gobuster_Linux_x86_64.tar.gz

# ===== INSTALLATION DE SUBFINDER =====
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder_2.6.3_linux_amd64.zip

# ===== CONFIGURATION DE L'APPLICATION =====
WORKDIR /app

# Copier les requirements d'abord (pour cache Docker)
COPY backend/requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY backend/ .

# ===== CRÉATION DES RÉPERTOIRES =====
RUN mkdir -p /app/scans \
    && mkdir -p /app/wordlists \
    && mkdir -p /app/reports

# ===== TÉLÉCHARGEMENT DES WORDLISTS =====
RUN wget -q https://github.com/danielmiessler/SecLists/archive/master.zip \
    && unzip master.zip \
    && mv SecLists-master /app/wordlists/seclists \
    && rm master.zip

# ===== HEALTHCHECK =====
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/api/status || exit 1

# ===== EXPOSITION DES PORTS =====
EXPOSE 5000

# ===== COMMANDE DE DÉMARRAGE =====
CMD ["python", "app.py"]

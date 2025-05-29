# Dockerfile - Toolbox v2 optimisé
FROM python:3.10-slim

# Métadonnées
LABEL maintainer="Toolbox Team"
LABEL version="2.0"
LABEL description="Toolbox Cybersécurité - Tests d'intrusion automatisés"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# ===== INSTALLATION DES DÉPENDANCES SYSTÈME =====
RUN apt-get update && apt-get install -y \
    # Outils de base
    curl \
    wget \
    git \
    build-essential \
    ca-certificates \
    gnupg \
    lsb-release \
    procps \
    \
    # Outils de sécurité
    nmap \
    sqlmap \
    \
    # Dépendances Python
    libpq-dev \
    libpcap-dev \
    python3-dev \
    \
    # Client PostgreSQL (pour futurs besoins)
    postgresql-client \
    \
    # Ruby pour Metasploit
    ruby \
    ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# ===== INSTALLATION DOCKER CLI =====
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# ===== INSTALLATION METASPLOIT =====
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall \
    && chmod 755 msfinstall \
    && ./msfinstall \
    && rm msfinstall

# ===== CONFIGURATION DE L'APPLICATION =====
WORKDIR /app

# Copier les requirements d'abord (pour cache Docker)
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY backend/ .

# Créer un utilisateur non-root pour plus de sécurité
RUN useradd --create-home --shell /bin/bash toolbox \
    && chown -R toolbox:toolbox /app

# ===== CONFIGURATION DES PERMISSIONS =====
# Garder root pour les outils qui en ont besoin (nmap, docker)
# USER toolbox

# ===== HEALTHCHECK =====
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/api/status || exit 1

# ===== EXPOSITION DES PORTS =====
EXPOSE 5000

# ===== COMMANDE DE DÉMARRAGE =====
CMD ["python", "app.py"]

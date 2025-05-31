# Dockerfile - Toolbox vierge
FROM python:3.10-slim

# Métadonnées
LABEL maintainer="Toolbox Team"
LABEL version="2.0"
LABEL description="Toolbox Cybersécurité - Infrastructure de base"

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
    procps \
    \
    # Dépendances Python
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ===== CONFIGURATION DE L'APPLICATION =====
WORKDIR /app

# Copier les requirements d'abord (pour cache Docker)
COPY backend/requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY backend/ .

# ===== HEALTHCHECK =====
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/api/status || exit 1

# ===== EXPOSITION DES PORTS =====
EXPOSE 5000

# ===== COMMANDE DE DÉMARRAGE =====
CMD ["python", "app.py"]

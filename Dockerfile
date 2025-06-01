FROM python:3.10-slim

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Installation des dépendances système de base
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    git \
    build-essential \
    nmap \
    libssl-dev \
    libssh-dev \
    make \
    gcc \
    ruby \
    && rm -rf /var/lib/apt/lists/*

# Installation des outils via pip/sources
RUN pip3 install sqlmap


# 3) Installer Metasploit Framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    chmod 755 msfinstall && \
    ./msfinstall && \
    rm msfinstall



# Installation de Nuclei
RUN wget -O /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip" && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Mise à jour des templates Nuclei
RUN nuclei -update-templates > /dev/null 2>&1 || true

# Installation de Nikto depuis les sources
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Installation de Hydra depuis les sources
RUN git clone https://github.com/vanhauser-thc/thc-hydra.git /opt/hydra && \
    cd /opt/hydra && \
    ./configure > /dev/null 2>&1 && \
    make > /dev/null 2>&1 && \
    make install > /dev/null 2>&1 && \
    cd / && rm -rf /opt/hydra || true

# Variables d'environnement Python
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Créer le répertoire de travail
WORKDIR /app

# Copier les requirements et installer les dépendances Python
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Exposer le port Flask
EXPOSE 5000

# Commande par défaut
CMD ["python", "app.py"]

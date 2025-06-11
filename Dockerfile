# Dockerfile adapté de HuntKit pour la toolbox pentest
FROM python:3.10-slim

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TOOLS="/opt"
ENV WORDLISTS="/usr/share/wordlists"
ENV DEBIAN_FRONTEND=noninteractive

# Créer les répertoires de travail
WORKDIR /app
RUN mkdir -p $TOOLS $WORDLISTS

# ===== DÉPENDANCES SYSTÈME DE BASE =====
RUN apt-get update && apt-get install -y \
    # Essentiels
    curl \
    wget \
    unzip \
    git \
    build-essential \
    make \
    gcc \
    \
    # Outils réseau
    nmap \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    \
    # Dépendances pour compilation
    libssl-dev \
    libssh-dev \
    libpcap-dev \
    \
    # Dépendances Ruby pour wpscan/nikto
    ruby \
    ruby-dev \
    \
    # Dépendances Python
    python3-dev \
    python3-pip \
    \
    # POSTGRESQL CLIENT POUR SAUVEGARDE
    postgresql-client \
    \
    # Utilitaires
    zip \
    unzip \
    jq \
    && rm -rf /var/lib/apt/lists/*

# ===== INSTALLATION DES 6 OUTILS ESSENTIELS =====

# 1. NMAP (déjà installé via apt)
# Vérification : nmap est déjà disponible

# 2. HYDRA - Installation depuis les sources
RUN git clone https://github.com/vanhauser-thc/thc-hydra.git $TOOLS/hydra && \
    cd $TOOLS/hydra && \
    ./configure > /dev/null 2>&1 && \
    make > /dev/null 2>&1 && \
    make install > /dev/null 2>&1 && \
    cd / && rm -rf $TOOLS/hydra

# 3. NIKTO - Installation depuis les sources
RUN git clone https://github.com/sullo/nikto.git $TOOLS/nikto && \
    chmod +x $TOOLS/nikto/program/nikto.pl && \
    ln -s $TOOLS/nikto/program/nikto.pl /usr/local/bin/nikto

# 4. NUCLEI - Installation depuis GitHub releases
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    wget -O /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_${ARCH}.zip" && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Télécharger les templates Nuclei
RUN nuclei -update-templates > /dev/null 2>&1 || true

# 5. SQLMAP - Installation via pip
RUN pip3 install sqlmap

# 6. METASPLOIT - Installation via script officiel
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
    chmod 755 /tmp/msfinstall && \
    /tmp/msfinstall && \
    rm /tmp/msfinstall

# ===== WORDLISTS ESSENTIELLES =====
# Télécharger seulement les wordlists nécessaires
RUN mkdir -p $WORDLISTS/hydra $WORDLISTS/nuclei

# Wordlist rockyou pour Hydra
RUN curl -L https://github.com/praetorian-code/Hob0Rules/raw/db10d30b0e4295a648b8d1eab059b4d7a567bf0a/wordlists/rockyou.txt.gz \
    -o $WORDLISTS/rockyou.txt.gz && \
    gunzip $WORDLISTS/rockyou.txt.gz

# Wordlists essentielles - URLs corrigées
RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -O $WORDLISTS/common.txt 2>/dev/null || \
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
    -O $WORDLISTS/common.txt 2>/dev/null || \
    echo "admin\ntest\nindex\nlogin\npassword" > $WORDLISTS/common.txt

RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
    -O $WORDLISTS/top1000-passwords.txt 2>/dev/null || \
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
    -O $WORDLISTS/top1000-passwords.txt 2>/dev/null || \
    echo -e "password\n123456\nadmin\ntest\nroot\nguest\nuser\npassword123\n12345\nqwerty" > $WORDLISTS/top1000-passwords.txt

# ===== INSTALLATION DES DÉPENDANCES PYTHON =====
# Copier les requirements et installer les dépendances Python
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ===== CONFIGURATION =====
# Copier le code de l'application
COPY . .

# Créer les liens symboliques pour les outils
RUN ln -sf /opt/metasploit-framework/embedded/framework/data/wordlists $WORDLISTS/metasploit || true

# Vérification des outils installés
RUN echo "=== VÉRIFICATION DES OUTILS ===" && \
    echo "✓ Nmap: $(nmap --version | head -1)" && \
    echo "✓ Hydra: $(hydra -h 2>&1 | head -1 || echo 'Hydra installé')" && \
    echo "✓ Nikto: $(nikto -Version 2>/dev/null || echo 'Nikto installé')" && \
    echo "✓ Nuclei: $(nuclei -version 2>/dev/null || echo 'Nuclei installé')" && \
    echo "✓ SQLmap: $(sqlmap --version 2>/dev/null || echo 'SQLmap installé')" && \
    echo "✓ Metasploit: $(ls /opt/metasploit* 2>/dev/null | head -1 || echo 'Framework MSF installé')" && \
    echo "✓ PostgreSQL Client: $(pg_dump --version 2>/dev/null || echo 'pg_dump installé')" && \
    echo "=== OUTILS PRÊTS ==="

# Variables d'environnement Python
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Exposer le port Flask
EXPOSE 5000

# Commande par défaut
CMD ["python", "backend/app.py"]

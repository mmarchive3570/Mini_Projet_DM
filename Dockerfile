# sudo docker build -t cryptoImage .
# Utilise une image officielle Python l�g�re
FROM python:3.12-slim

# R�pertoire de travail
WORKDIR /app

# Copie les fichiers du projet dans le conteneur

COPY . /app
WORKDIR /app

# Installation des d�pendances syst�me si besoin
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Installation des d�pendances Python
RUN pip install --no-cache-dir pycryptodome \
    && pip install --no-cache-dir fastapi uvicorn \
    && pip install python-multipart
    


# Commande par d�faut (modifiable avec docker-compose)
#CMD ["python", "main.py"]
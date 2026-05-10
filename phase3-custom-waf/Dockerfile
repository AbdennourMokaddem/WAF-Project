FROM python:3.11-slim

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code source du WAF
COPY . .

# Créer le dossier logs
RUN mkdir -p /app/logs

EXPOSE 8080

CMD ["python", "main.py"]

FROM python:3.10-slim

# On crée et utilise un dossier de travail
WORKDIR /app

# Copier le fichier requirements.txt dans le conteneur, puis installer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du code
COPY . .

# Commande de lancement
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

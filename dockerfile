# Dockerfile
FROM node:18

# Crée le dossier de travail
WORKDIR /app

# Copie package.json et package-lock.json
COPY package*.json ./

# Installe les dépendances
RUN npm install

# Copie tout le reste du projet
COPY . .

# Expose le port que Render va utiliser
EXPOSE 4000

# Définit la variable d'environnement par défaut (Render peut la remplacer)
ENV PORT=5432

# Commande pour lancer le backend
CMD ["node", "index.js"]


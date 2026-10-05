# Reveo — Web

Application web de Reveo : gestion d'alertes (réveils, rendez-vous, rappels, départs) synchronisées par Bluetooth vers un bracelet connecté (LilyGO T-Watch S3), avec alerte visuelle + vibration — pensé pour les personnes sourdes ou malentendantes.

En ligne sur [reveo.benross.ch](https://reveo.benross.ch).

## Stack

- **Backend** : Node.js / Express, base SQLite (`better-sqlite3`)
- **Frontend** : une seule page HTML/CSS/JS, sans framework ni build
- **Comptes** : partagés avec [grade.benross.ch](https://grade.benross.ch) — même table `users`, connexion unique (SSO) via un cookie commun sur `.benross.ch`
- **Montre** : connexion en Bluetooth Web (Chrome/Edge sur ordinateur ou Android — non supporté par Safari iOS)

## Structure

```
web/
├── server.js             API (auth, profil, alertes)
├── package.json
├── ecosystem.config.js   config PM2 pour la prod
├── public/
│   └── index.html        toute l'interface
└── .env.example
```

## Installation locale

```bash
cd web
npm install
cp .env.example .env     # puis renseigner les variables ci-dessous
npm start
```

## Variables d'environnement

| Variable | Description |
|---|---|
| `PORT` | Port d'écoute du serveur |
| `JWT_SECRET` | Secret de signature des tokens Reveo |
| `SSO_SECRET` | Secret partagé avec Grade, pour le cookie de connexion unique |
| `GRADE_DB_PATH` | Chemin vers `grades.db` (base partagée contenant la table `users`) |

> Sans un accès à la base `grades.db` de Grade, l'inscription/connexion ne fonctionnera pas : c'est cette table qui est la source des comptes.

## Déploiement

Géré par PM2 derrière Nginx (reverse proxy + certificat Let's Encrypt). Voir `ecosystem.config.js`.

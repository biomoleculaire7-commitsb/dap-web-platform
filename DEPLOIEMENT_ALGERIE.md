[DEPLOIEMENT_ALGERIE.md](https://github.com/user-attachments/files/34493441/DEPLOIEMENT_ALGERIE.md)
# Passage sur un serveur en Algérie (Docker)

## Prérequis
VPS Linux (Ubuntu 22.04+), 2 vCPU / 4 Go RAM minimum, hébergé en Algérie ; un nom de domaine pointant vers l'IP du serveur ; Docker + Docker Compose.

## Étapes
1. Copier le projet sur le serveur : `git clone <votre-dépôt> dap && cd dap`
2. `cp .env.example .env` puis éditer `.env` (mot de passe central long, `DOMAIN`, `DAP_ORIGINS=https://votre-domaine.dz`, `DAP_SEED_DEMO=0` pour la production).
3. `docker compose up -d --build` → l'application est disponible en HTTPS sur `https://votre-domaine.dz` (certificat automatique).
4. Se connecter avec le compte central et approuver les établissements.

## Sauvegarde (obligatoire)
Le volume `dap_data` contient la base, les images et le dataset. Exemple (cron quotidien) :
`docker run --rm -v dap_dap_data:/data -v /sauvegardes:/b alpine tar czf /b/dap_$(date +%F).tgz /data`
(le nom du volume dépend du dossier du projet : vérifier avec `docker volume ls`).

## Mise à jour
`git pull && docker compose up -d --build`

## Limites connues de cette version
SQLite (un seul serveur, pas de haute disponibilité) ; fichiers sur disque local ; pas de récupération de mot de passe ni d'envoi d'e-mails ; pas d'authentification à deux facteurs ; traitement des vidéos synchrone.

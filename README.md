[README.md](https://github.com/user-attachments/files/34493111/README.md)
# DAP — Plateforme de diagnostic automatique des parasites

FastAPI + SQLite · modèle `exp.tflite` (YOLO, 19 classes) · interface FR/AR (RTL) · rapport PDF bilingue.

## Rôles
| Rôle | Accès |
|---|---|
| **central** (vous, puis le ministère) | approuve les établissements, valide les annotations d'experts, télécharge le dataset validé, base parasites du réseau (anonymisée), journal d'audit. **Aucun accès aux dossiers patients.** |
| **admin** (établissement) | gère son équipe, voit ses dossiers |
| **expert** | confirme/infirme, annote (liste de 50 classes), rédige l'expertise (établissement déclaré « avec expert » uniquement) |
| **tech** | crée des dossiers, importe images/vidéos/documents, envoie pour expertise |

## Flux
1. Un établissement s'inscrit → statut *en attente* → l'administration centrale l'approuve → il peut se connecter.
2. Dossier patient → analyse IA (seuil `DAP_CONF`, 0.80 par défaut) → envoi à un établissement avec expert.
3. L'expert confirme/infirme, annote, envoie le rapport → retour au laboratoire demandeur → **compte rendu PDF** (format laboratoire algérien, FR/AR, zones signature et cachet).
4. Les annotations restent *en attente* dans `dataset_pending/` ; **seule la validation centrale** les copie dans `dataset/` (format YOLO exportable).
5. Chaque établissement ne voit que ses propres résultats.

## Lancement local
    pip install -r requirements.txt
    DAP_CENTRAL_PASSWORD='MotDePasseLong' DAP_SEED_DEMO=1 uvicorn main:app --port 8000
Ouvrir http://localhost:8000. Comptes démo (si `DAP_SEED_DEMO=1`) : `labo@dap.local`, `expert@dap.local` / mot de passe `DAP_DEMO_PASSWORD` (défaut `demo1234`). Compte central : `DAP_CENTRAL_EMAIL` (défaut `central@dap.local`) ; sans `DAP_CENTRAL_PASSWORD`, un mot de passe aléatoire est affiché dans les journaux au premier démarrage.

## Variables d'environnement
`DAP_DATA` dossier des données · `DAP_MODEL` chemin du .tflite · `DAP_CONF` seuil de confiance · `DAP_ORIGINS` origines CORS (Vercel) · `DAP_SESSION_HOURS` durée de session · `DAP_CENTRAL_EMAIL` / `DAP_CENTRAL_PASSWORD` · `DAP_SEED_DEMO` / `DAP_DEMO_PASSWORD`.

## Déploiement
- **Démonstration** : Render (voir `render.yaml`), l'application sert aussi l'interface (adresse Render directe). Vercel est facultatif (dossier `web/`, `config.js` = adresse Render).
- **Serveur en Algérie** (VPS + Docker) : voir `DEPLOIEMENT_ALGERIE.md`.

`labels.txt` = ordre des classes 0–18 du modèle ; les classes ajoutées (19+) sont définies dans `main.py` (ne jamais réordonner).

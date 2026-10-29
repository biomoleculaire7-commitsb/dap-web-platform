[README.md](https://github.com/user-attachments/files/34139501/README.md)
# DAP — Plateforme de diagnostic automatique des parasites

FastAPI + SQLite, inférence `exp.tflite` (YOLOv8, 19 classes), frontend web intégré.

## Lancement
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000
Variables : `DAP_DATA` (base + fichiers), `DAP_MODEL` (chemin du .tflite).

## Flux
1. Inscription du labo/hôpital (cocher « dispose d'un expert » si applicable) ; l'admin ajoute techniciens/experts.
2. Dossier patient → images, vidéos (~12 images extraites), documents → détection IA + images annotées.
3. « Envoyer pour expertise » vers un établissement avec expert (dossier complet visible chez lui).
4. L'expert confirme/infirme chaque détection, rédige le rapport → retour au labo demandeur.
5. Base parasites : détections confirmées du réseau (anonymisées pour les autres établissements).

`labels.txt` = ordre des classes 0–18 du dataset Ultralytics : vérifiez-le par rapport à votre entraînement.

## Production
HTTPS, PostgreSQL, stockage objet, expiration des sessions, journal d'audit, conformité loi 18-07 (données personnelles).

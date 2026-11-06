[NOTE_PROJET_18_NOVEMBRE.md](https://github.com/user-attachments/files/34493178/NOTE_PROJET_18_NOVEMBRE.md)
# DAP — Note pour la présentation du 18 novembre

## Ce que montre la démonstration
Inscription d'un établissement → **approbation centrale** → dossier patient → détection IA (19 parasites) → envoi à un expert → annotation (50 classes) et rapport → **compte rendu PDF bilingue** → validation centrale des annotations → dataset prêt pour réentraînement. Interface FR/AR.

## Points à dire honnêtement
- **Précision du modèle** : mAP50 0,982 sur les images de validation du jeu de données public ; ces images viennent de la même source que l'entraînement (jeu Roboflow/Ultralytics). La performance sur des images de laboratoires algériens n'est **pas encore mesurée**. C'est la première étape de validation à mener avec les laboratoires partenaires.
- **Classe faible** : Chilomastix mesnili (mAP50 0,76, 22 instances de validation) ; Entamoeba histolytica/dispar n'a que 7 instances de validation.
- **Rôle de l'IA** : aide au diagnostic ; la décision finale revient à l'expert (mentionné sur chaque compte rendu).
- **Données de santé** : la démonstration est hébergée à l'étranger (Render). **Aucune donnée réelle de patient ne doit y être saisie.** L'utilisation réelle exige un hébergement en Algérie et une conformité à la loi 18-07 (autorisation/déclaration auprès de l'autorité de protection des données personnelles, consentement) — à vérifier avec un juriste.
- **Base centrale** : les annotations d'experts ne rejoignent le dataset d'entraînement qu'après validation de l'administration centrale (vous, puis le ministère de la Santé si elle est adoptée).

## Étapes suivantes proposées
1. Financement → VPS en Algérie (voir `DEPLOIEMENT_ALGERIE.md`).
2. Test sur images réelles de 2–3 laboratoires pilotes ; mesure de la précision et des faux positifs.
3. Réentraînement avec les annotations validées ; suivi des versions du modèle.
4. Conformité juridique (loi 18-07), hébergement, PostgreSQL, e-mails de notification, récupération de mot de passe.
5. Lien avec PULSE (données confirmées, sans identité patient).

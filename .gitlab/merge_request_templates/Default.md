## Objet
<!-- Que change cette MR et pourquoi ? Lien vers l'issue : #… -->

## Type
- [ ] feat  - [ ] fix  - [ ] sec  - [ ] infra  - [ ] docs

## Checklist sécurité
- [ ] Aucun secret, jeton ou mot de passe ajouté (gitleaks vert)
- [ ] Entrées utilisateur validées / requêtes SQL paramétrées
- [ ] Nouvelles dépendances justifiées et versions figées (pip-audit vert)
- [ ] Tests ajoutés ou mis à jour (pytest vert)
- [ ] Si `infra/` modifié : `terraform plan` relu, Checkov vert, exceptions justifiées
- [ ] Documentation (README) à jour si l'architecture change

## Comment tester
<!-- Étapes pour le relecteur -->

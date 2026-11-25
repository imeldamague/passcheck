# Contribuer à PassCheck

## Workflow Git (GitLab Flow)

```
main  ●─────────●──────────●──────────●   (protégée, toujours déployable, taguée vX.Y.Z)
       \       /  \       /  \       /
        feature/…    fix/…     infra/…    (1 branche = 1 sujet, durée de vie courte)
```

1. Partir d'une `main` à jour : `git switch main && git pull`
2. Créer une branche nommée selon le type :
   `feature/<sujet>`, `fix/<sujet>`, `sec/<sujet>`, `infra/<sujet>`, `docs/<sujet>`
3. Commits petits et atomiques, au format **Conventional Commits** :
   `feat: ajout de la page de connexion` · `fix: timeout manquant` · `sec: passage à Argon2id`
4. `git push -u origin <branche>`, puis ouvrir une **Merge Request** (le modèle se charge automatiquement)
5. Fusion seulement si : **pipeline verte**, **≥ 1 approbation d'un autre membre**, **fils résolus**
6. Fusion en *squash* (historique de `main` lisible), puis suppression de la branche
7. Release : tag SemVer signé sur `main` → `git tag -s v1.0.0 -m "v1.0.0" && git push --tags`

## Règles de sécurité de l'équipe

| Règle | Mise en œuvre |
|---|---|
| Pas de push direct sur `main` | Branche protégée : *Allowed to push* = **No one** |
| Pas de fusion sans revue ni pipeline verte | Settings → Merge requests : *Pipelines must succeed*, *All threads must be resolved* |
| Revue obligatoire des fichiers sensibles | `.gitlab/CODEOWNERS` (infra, CI, Dockerfile) |
| Commits signés | `git config commit.gpgsign true` (clé SSH ou GPG déclarée dans GitLab) |
| Aucun secret dans Git | `.gitignore`, hook pre-commit gitleaks, job gitleaks sur tout l'historique |
| Comptes protégés | 2FA obligatoire sur le groupe, jetons à durée limitée et portée minimale |
| Moindre privilège | 1 Maintainer, les autres membres Developer ; variables CI *Protected + Masked* |

En cas de secret poussé par erreur : **révoquer immédiatement le secret** (le supprimer de l'historique ne suffit pas), puis prévenir le Maintainer.

## Rôles

| Rôle GitLab | Qui | Droits |
|---|---|---|
| Maintainer | Référent sécurité / infra | Paramètres, variables CI, `infra_apply` et `infra_destroy` en production |
| Developer | Autres membres | Branches, MR, revue, lancement des pipelines |
| Reporter | Formateur (lecture) | Consultation du code et des pipelines |

## Avant de pousser

```bash
pip install -r requirements-dev.txt pre-commit
pre-commit install          # une fois
python -m pytest            # 19 tests
flake8 app tests
```

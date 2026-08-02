# Revue de sécurité — état cumulé

Date : 2 août 2026. Version examinée : 0.17.0.

## Résultat

La revue interne n'a plus de constat critique ou élevé connu dans le code, les
dépendances Python verrouillées ou l'image applicative. Elle a conduit à
durcir l'authentification, l'audit, les mises à jour, les restaurations et
l'installation. Ce résultat ne remplace pas un pentest ni la validation sur un
véritable cluster Proxmox.

## Preuves automatisées

| Contrôle | Résultat |
|---|---|
| Tests Pytest et couverture | seuil obligatoire de 95 % |
| Ruff et mypy | analyse statique sans erreur |
| Bandit | aucun constat actif |
| pip-audit sur `requirements.lock` | aucune vulnérabilité connue |
| Gitleaks sur tout l'historique | aucun secret détecté après une exclusion étroite et documentée du JDBC Keycloak |
| Docker Scout sur `proxmox-vm-portal:0.17.0` | 0 critique, 0 élevée, 0 moyenne, 0 faible |
| Actionlint et contrôleur de release | workflows valides, actions par SHA et cohérence SemVer |
| Vérification de déploiement | image GHCR par digest et identité OIDC exacte obligatoires en mode release |
| Image Cosign v3.0.6 épinglée | signature officielle, certificat et entrée de transparence vérifiés |

La base d'image est `python:3.13.14-alpine3.24` épinglée par digest. Les
dépendances Python transitives sont verrouillées avec leurs hashes dans
`requirements.lock`. Trivy n'a pas été retenu pour cette revue à cause de
l'incident de chaîne d'approvisionnement publié en mars 2026 ; Docker Scout a
été utilisé pour l'image et plusieurs outils indépendants pour le dépôt.

## Test d'installation Debian vierge

`deploy/testing/test-debian-install.sh` démarre un conteneur privilégié
`debian:13-slim` sans monter le socket Docker de l'hôte, copie le dépôt, puis
exécute le véritable `install-debian.sh` en mode de validation. Un adaptateur
`systemctl` démarre un daemon Docker imbriqué avec le pilote VFS, nécessaire
uniquement parce que le banc est lui-même conteneurisé.

Le test vérifie l'installation de Docker depuis son dépôt officiel et la
construction de l'image non-root par le lockfile. Les migrations PostgreSQL,
healthchecks et options de conteneur sont testés séparément par la stack Compose
sur l'hôte. Le mode de validation s'arrête avant de tirer et lancer toute la
stack afin d'éviter une forte duplication de stockage dans Docker imbriqué. Il
ne valide pas systemd, nftables, le réseau d'une VM, un certificat ACME public,
un redémarrage du noyau, les ACL d'un Proxmox réel ni une restauration de volume.

## Corrections issues de la revue

- limitation de connexion persistante et distribuée, sans conserver le nom ou
  l'adresse IP bruts dans les clés d'audit ;
- journal PostgreSQL rendu append-only et index dédié à la limitation ;
- suppression des assertions utilisées comme contrôles en production ;
- restauration protégée contre traversées de chemins et liens d'archive ;
- mise à jour limitée à un commit `origin/main` attendu et vérifié ;
- dépôt d'installation obligatoirement détenu par root et non modifiable par
  groupe ou autres ;
- image Alpine minimale, digest épinglé, dépendances avec hashes et règle
  Gitleaks versionnée.
- image et manifeste de release signés par identité OIDC, avec SBOM et provenance ;
- installation et mise à jour refusant les images publiées sans digest ni
  signature correspondant au dépôt et au tag approuvés.

## Décision

La version 0.17.0 peut servir aux essais privés et à la recette. La publication
open source et l'exposition Internet restent conditionnées aux six risques
résiduels du modèle de menaces, en priorité le test sur VM Debian réelle, les
ACL Proxmox, la MFA et le pentest indépendant.

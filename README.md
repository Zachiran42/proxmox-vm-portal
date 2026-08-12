# Portail Proxmox VM

Portail Web Flask de provisionnement de VM Proxmox, avec catalogue d'images,
comptes locaux, rôles, quotas et journal d'audit PostgreSQL. Aucun secret n'est
stocké dans le dépôt.

## Sécurité intégrée

- Authentification locale obligatoire pour `POST /api/vms`, par session signée HttpOnly et SameSite=Lax.
- Le mot de passe administrateur est fourni uniquement sous forme de hash Werkzeug (`PORTAL_ADMIN_PASSWORD_HASH`) ; aucun mot de passe clair n'est accepté en configuration.
- Le cookie de session est `Secure` par défaut. `PORTAL_SESSION_COOKIE_SECURE=false` est réservé au développement HTTP local isolé.
- La configuration PVE et les secrets d'authentification sont lus depuis l'environnement. L'application refuse de démarrer s'il manque un secret d'authentification.
- En conteneur, les valeurs sensibles sont montées comme secrets et lues via
  les variantes `*_FILE`; elles ne figurent ni dans Git ni dans l'environnement
  inspectable du conteneur.
- Taille maximale des requêtes : 64 KiB.
- Les erreurs de transport, TLS, JSON invalide et HTTP PVE sont converties en JSON 502/503 sans détail PVE ni traceback.
- Authentification PVE par API token dédié : les tokens `root@…` sont explicitement refusés ; HTTPS est obligatoire.
- Validation stricte en liste blanche : nom, nœud, profil d'image approuvé, CPU (1–32), RAM (512–131072 MiB, pas de 256), disque (8–2048 GiB).
- Avant toute création, le worker vérifie que le profil est actif et que son ISO exacte est présente sur le nœud choisi.
- Les rôles `admin`, `operator` et `user` ainsi que les quotas CPU, RAM, disque
  et nombre de VM sont appliqués côté serveur.
- Une réservation en base précède l'appel Proxmox afin de rendre les quotas sûrs
  face aux demandes concurrentes.
- Les connexions, refus d'autorisation, créations d'utilisateurs et demandes de
  VM alimentent un journal d'audit sans mot de passe ni secret Proxmox.
- Keycloak peut authentifier les utilisateurs par OIDC Authorization Code avec
  PKCE S256 ; les rôles externes sont mappés strictement et les jetons ne sont
  pas conservés.
- PostgreSQL porte une file de travaux verrouillée par worker. Le suivi du UPID
  Proxmox distingue réussite, échec et résultat ambigu nécessitant une revue.
- Le démarrage, l’arrêt propre, le redémarrage et la suppression suivent la même
  file persistante. Une seule opération peut être active par VM et les quotas ne
  sont libérés qu’après confirmation de suppression par Proxmox.
- L’administration expose la santé de PostgreSQL, du worker et de Proxmox ainsi
  que les travaux ambigus. Un suivi ne peut être repris qu’avec son UPID existant
  et une clôture en échec exige la confirmation exacte du nom de la VM.
- Les métriques Prometheus utilisent un jeton Bearer dédié et ne contiennent
  aucun identifiant individuel. Les alertes email/webhook sont déléguées à
  Alertmanager afin de ne jamais bloquer le worker.
- Les tags de release construisent une image GHCR signée par identité OIDC, avec
  provenance `mode=max`, SBOM SPDX, manifeste signé et sommes SHA-256. Aucune clé
  de signature longue durée n'est stockée dans GitHub.
- Le mode de déploiement `release` refuse les tags d'image mutables, vérifie la
  signature et l'identité OIDC avec Cosign, puis exécute uniquement le digest
  GHCR approuvé sans reconstruire le code local.
- Les profils cloud-init clonés créent un compte nominatif non-root. L'utilisateur
  choisit son mot de passe SSH selon une longueur minimale administrable, sans
  règle de complexité imposée. Le secret reste chiffré pendant le travail puis
  est supprimé dès son injection dans cloud-init.

Le token de service PVE doit être limité par ACL aux nœuds, stockages et opérations requis. N'utilisez jamais `root@pam`.

## Configuration et lancement local

```bash
cd /opt/proxmox-vm-portal
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
# Renseigner uniquement .env local, non versionné, puis générer hash et secret selon les commandes commentées.
set -a; . ./.env; set +a
flask --app 'portal:create_app' db upgrade
flask --app 'portal:create_app' bootstrap-admin  # uniquement sur une base vide
flask --app 'portal:create_app' run
# Dans un second service/processus :
flask --app 'portal:create_app' worker
```

Récupération d'un administrateur local existant (saisie masquée, sans
modifier les autres comptes ni la base) :

```bash
sudo /opt/proxmox-vm-portal/deploy/scripts/reset-admin-password.sh
```

Une installation plug-and-play neuve utilise temporairement `admin/admin`.
Après cette première authentification, le portail bloque toutes les fonctions
jusqu'au choix d'un nouveau mot de passe. Sa longueur est laissée à la politique
de l'administrateur ; l'interface refuse uniquement une valeur vide et une
réutilisation du mot de passe temporaire.

Le raccordement Proxmox est interactif et valide automatiquement l'URL, la CA,
le token et la permission `Sys.Audit` avant de redémarrer le portail :

```bash
sudo /opt/proxmox-vm-portal/deploy/scripts/configure-proxmox.sh
sudo /opt/proxmox-vm-portal/deploy/scripts/check-proxmox.sh
```

Avec une CA Proxmox historique, le client conserve la validation de chaîne, du
nom d'hôte et `CERT_REQUIRED`, mais désactive uniquement `X509_STRICT` pour
accepter l'absence ancienne de l'extension `keyUsage`.

L'interface Web est disponible sur `/`. Un administrateur peut y publier,
contrôler, suspendre et réactiver les profils d'images ; les autres rôles voient
le catalogue actif en lecture seule. Chaque utilisateur dispose d'un assistant
de création de VM, d'une vue de ses quotas et d'un historique privé actualisé
automatiquement. L'identifiant SSH apparaît seulement dans l'espace du propriétaire.
Les machines prêtes peuvent être démarrées, arrêtées et redémarrées depuis cette
vue. La suppression définitive exige de saisir le nom exact de la VM.
L'espace Administration permet de créer et suspendre les comptes locaux,
d'ajuster leurs rôles et quotas et de consulter les 100 derniers événements
d'audit. Il centralise aussi l’état des services et les interventions manuelles
sur les travaux ambigus. Les rôles des identités OIDC restent gérés dans Keycloak.
Le journal d’audit peut être exporté en CSV neutralisé pour les tableurs.

En production, servez l'application derrière TLS avec un serveur WSGI et conservez `PORTAL_SESSION_COOKIE_SECURE=true`. N'activez pas le mode debug.

## Déploiement Debian avec Docker

La stack de production fournit PostgreSQL 17, un service de migration, l'API
Gunicorn non-root, le worker et Caddy. Keycloak et Password Pusher sont des
profils Compose optionnels. Après configuration de `.env.production` :

```bash
sudo bash deploy/scripts/install-debian.sh
sudo deploy/scripts/compose.sh ps
```

Guide complet : [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). Sauvegarde,
restauration et mises à jour :
[`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md).
Pour un réseau autonome sans accès GitHub/GHCR depuis le serveur, utilisez le
bundle vérifiable décrit dans [`docs/AIRGAP.md`](docs/AIRGAP.md).

Pour tester la release privée sur une Debian vierge avec une commande `curl`
épinglée au tag, utilisez la procédure d'installation rapide de
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md#installation-rapide-de-la-release-privée).

## Tests

Les tests n'appellent aucun PVE réel et n'utilisent aucun secret réel :

```bash
.venv/bin/pytest -q
```

Architecture cible et étapes de livraison : [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Modèle de menaces et preuves de la revue :
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) et
[`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).
Recette de qualification réelle : [`docs/PREPRODUCTION.md`](docs/PREPRODUCTION.md).
Configuration Keycloak et LDAP/LDAPS : [`docs/KEYCLOAK.md`](docs/KEYCLOAK.md).
Exploitation de la file de travaux : [`docs/JOBS.md`](docs/JOBS.md).
Préparation sécurisée des templates et remise des accès : [`docs/GUEST_ACCESS.md`](docs/GUEST_ACCESS.md).
Construction reproductible des templates Debian depuis l'ISO :
[`docs/IMAGE_FACTORY.md`](docs/IMAGE_FACTORY.md).
Métriques, règles d’alerte et export d’audit :
[`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md).
Publication, SBOM, provenance et vérification des signatures :
[`docs/RELEASES.md`](docs/RELEASES.md).

Endpoints : `GET /healthz`, `GET /metrics`, `GET /`, `POST /login`, `POST /logout`,
`GET /api/me`, `POST /api/me/password`, `GET /api/nodes`, `GET /api/nodes/<node>/isos`,
`GET /api/image-profiles`, `POST /api/vms`, `POST /api/vms/<id>/actions`,
`GET /api/jobs`, `GET /api/jobs/<id>`,
`GET|POST /api/admin/users`, `PATCH /api/admin/users/<id>`,
`GET /api/admin/audit-events`, `GET /api/admin/audit-events.csv`,
`GET /api/admin/operations`, `POST /api/admin/incidents/<kind>/<id>/actions`,
`GET|POST /api/admin/image-profiles`, `PATCH /api/admin/image-profiles/<slug>`,
`GET /auth/oidc/login` et `GET /auth/oidc/callback`.

Exemple de connexion :

```json
{"username":"admin","password":"votre-mot-de-passe-local"}
```

La réponse contient un jeton CSRF à envoyer dans l'en-tête `X-CSRF-Token` pour
`POST /api/vms`, `POST /api/vms/<id>/actions` et `POST /logout`.

Exemple de demande authentifiée (avec cet en-tête) :

```json
{"name":"web-01","node":"pve-a","profile":"debian-12","cpu":2,"ram_mb":4096,"disk_gb":40}
```

La réponse HTTP 202 contient `job_id`. Consultez ensuite
`GET /api/jobs/<job_id>` jusqu'à l'état terminal `succeeded`, `failed` ou
`attention`.

Avant la première demande, un administrateur doit publier au moins un profil
avec `POST /api/admin/image-profiles`, par exemple :

```json
{"slug":"debian-12","label":"Debian 12","description":"ISO approuvée","source_type":"iso","iso":"local:iso/debian-12.iso"}
```

Un profil cloud-init utilise à la place `source_type: "cloud_init"`,
`template_node` et `template_vmid`. La demande de VM doit alors inclure un
`guest_username` Linux non-root et un `guest_password` choisi par l'utilisateur.
Le mot de passe n'est jamais retourné par l'API. Lors de la publication, le portail
vérifie immédiatement que le VMID désigne bien un template Proxmox disponible.

La recette `images/packer/debian-13.pkr.hcl` construit automatiquement le
template Debian 13.6 durci depuis l'ISO officielle vérifiée. Après sa promotion,
un utilisateur choisit simplement « Debian 13 Cloud », ses ressources et son
nom de compte : le portail clone le système déjà installé, configure cloud-init,
démarre la VM. Voir `docs/IMAGE_FACTORY.md` et
`docs/GUEST_ACCESS.md`.

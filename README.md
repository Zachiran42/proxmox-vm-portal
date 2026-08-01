# Portail Proxmox VM

MVP Flask de demande de provisionnement de VM Proxmox, avec comptes locaux,
rôles, quotas et journal d'audit PostgreSQL. Aucun secret n'est stocké dans le
dépôt.

## Sécurité intégrée

- Authentification locale obligatoire pour `POST /api/vms`, par session signée HttpOnly et SameSite=Lax.
- Le mot de passe administrateur est fourni uniquement sous forme de hash Werkzeug (`PORTAL_ADMIN_PASSWORD_HASH`) ; aucun mot de passe clair n'est accepté en configuration.
- Le cookie de session est `Secure` par défaut. `PORTAL_SESSION_COOKIE_SECURE=false` est réservé au développement HTTP local isolé.
- La configuration PVE et les secrets d'authentification sont lus depuis l'environnement. L'application refuse de démarrer s'il manque un secret d'authentification.
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

En production, servez l'application derrière TLS avec un serveur WSGI et conservez `PORTAL_SESSION_COOKIE_SECURE=true`. N'activez pas le mode debug.

## Tests

Les tests n'appellent aucun PVE réel et n'utilisent aucun secret réel :

```bash
.venv/bin/pytest -q
```

Architecture cible et étapes de livraison : [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Configuration Keycloak et LDAP/LDAPS : [`docs/KEYCLOAK.md`](docs/KEYCLOAK.md).
Exploitation de la file de travaux : [`docs/JOBS.md`](docs/JOBS.md).

Endpoints : `GET /healthz`, `GET /`, `POST /login`, `POST /logout`,
`GET /api/me`, `GET /api/nodes`, `GET /api/nodes/<node>/isos`,
`GET /api/image-profiles`, `POST /api/vms`, `GET /api/jobs/<id>`,
`GET|POST /api/admin/users`, `GET /api/admin/audit-events`,
`GET|POST /api/admin/image-profiles`, `PATCH /api/admin/image-profiles/<slug>`,
`GET /auth/oidc/login` et `GET /auth/oidc/callback`.

Exemple de connexion :

```json
{"username":"admin","password":"votre-mot-de-passe-local"}
```

La réponse contient un jeton CSRF à envoyer dans l'en-tête `X-CSRF-Token` pour
`POST /api/vms` et `POST /logout`.

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
{"slug":"debian-12","label":"Debian 12","description":"ISO approuvée","iso":"local:iso/debian-12.iso"}
```

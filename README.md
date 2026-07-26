# Portail Proxmox VM

Socle MVP Flask pour demander le provisionnement de VM Proxmox. Il est conçu pour des comptes locaux au départ et une intégration Keycloak/OIDC ultérieure. Aucun secret n'est stocké dans le dépôt.

## Sécurité intégrée

- Configuration PVE uniquement par variables d'environnement ; `.env` est ignoré par Git.
- Authentification PVE par API token dédié : les tokens `root@…` sont explicitement refusés.
- HTTPS obligatoire pour l'API PVE.
- Validation stricte en liste blanche : nom, nœud, ISO, CPU (1–32), RAM (512–131072 MiB, pas de 256), disque (8–2048 GiB).
- Avant toute création, l'ISO est interrogée dans le stockage du nœud choisi. Une ISO `local` ne peut donc pas être employée depuis un autre nœud.
- Le client PVE est injectable, ce qui garantit des tests sans connexion à Proxmox.

Le token de service doit être créé côté PVE avec des ACL minimales, limitées aux nœuds, stockages et opérations nécessaires. N'utilisez jamais `root@pam`.

## Lancement local

```bash
cd /opt/proxmox-vm-portal
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
# Renseigner les vraies valeurs uniquement dans .env local (non versionné).
set -a; . ./.env; set +a
flask --app 'portal:create_app' run --debug
```

Pour les tests (sans PVE réel) :

```bash
pytest -q
```

Endpoints : `GET /healthz`, `GET /`, `POST /api/vms`.

Exemple de requête :

```json
{"name":"web-01","node":"pve-a","iso":"local:iso/debian-12.iso","cpu":2,"ram_mb":4096,"disk_gb":40}
```

Le MVP ne fournit pas encore d'authentification utilisateur ni de déploiement ; placez-le derrière un contrôle d'accès approprié avant exposition réseau.

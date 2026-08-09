# Déploiement reproductible sur Debian

## Prérequis

- une VM Debian 12 ou 13 à jour, avec au moins 2 vCPU, 4 Gio de RAM et 30 Gio de disque ;
- des enregistrements DNS pointant vers la VM pour le portail et, si activés,
  Keycloak et Password Pusher ;
- TCP 80/443 entrants et HTTPS sortant vers Proxmox ;
- un token API Proxmox non-root limité par ACL ;
- une clé `age` dont la clé privée est conservée hors de cette VM.

Le profil Password Pusher OSS publié en 2.9.0 est limité à `linux/amd64`. Le
socle du portail et le profil Keycloak ne dépendent pas de cette option.

Le script installe Docker depuis le dépôt APT officiel. Il ne modifie ni SSH ni
le pare-feu : ces changements dépendent du mode d'administration de la VM et
doivent être appliqués sans risquer de couper l'accès. Les seuls ports publiés
par Compose sont 80 et 443. Toutes les images tierces sont épinglées par version
et digest ; leur mise à jour est donc une modification de code revue.

Pour déployer une image publiée, utilisez exclusivement la référence par digest
issue du `release-manifest.json` et vérifiez d'abord sa signature selon
`docs/RELEASES.md`. Un tag, y compris `latest`, reste mutable et ne constitue pas
une preuve d'approbation.

Deux modes sont disponibles :

- `PORTAL_DEPLOY_MODE=source` construit localement le commit Git approuvé ;
- `PORTAL_DEPLOY_MODE=release` supprime les directives Compose `build`, vérifie
  la signature distante puis tire uniquement l'image GHCR par digest.

Pour le mode release privé, authentifiez le compte root de la VM avec un token
GitHub limité à `read:packages`, puis configurez `.env.production` :

```bash
sudo docker login ghcr.io

PORTAL_DEPLOY_MODE=release
PORTAL_IMAGE=ghcr.io/hugofelix088-spec/proxmox-vm-portal@sha256:DIGEST_RELEASE
PORTAL_RELEASE_TAG=v0.18.3
PORTAL_RELEASE_REPOSITORY=hugofelix088-spec/proxmox-vm-portal
PORTAL_RELEASE_TRANSPARENCY=private
```

Le digest provient de `release-manifest.json`. L'installateur exécute Cosign
v3.0.6 depuis son image officielle épinglée par digest, avec racine en lecture
seule, capacités supprimées et configuration Docker montée en lecture seule.
Le mode `public` interdit l'ignorance du journal Rekor ; ne l'activez qu'après
avoir publié les signatures avec transparence lors du passage open source.

## Installation rapide de la release privée

Tant que le dépôt et GHCR sont privés, créez un personal access token **classic**
temporaire avec `repo` et `read:packages`. Collez ensuite ce bloc dans une VM
Debian 12 ou 13 vierge. Le script est téléchargé depuis le tag immuable et non
depuis `main`; il récupère lui-même le digest du manifeste de release, refuse un
répertoire `/opt/proxmox-vm-portal` existant et vérifie la signature de l'image
avant son téléchargement.

```bash
read -rsp "Token GitHub temporaire : " PORTAL_GITHUB_TOKEN && echo
export PORTAL_GITHUB_TOKEN
export PORTAL_GITHUB_USERNAME="hugofelix088-spec"
bootstrap=$(mktemp)
printf 'header = "Authorization: Bearer %s"\n' "$PORTAL_GITHUB_TOKEN" | \
curl --config - --proto '=https' --tlsv1.2 --fail --silent --show-error \
  -H "Accept: application/vnd.github.raw+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/hugofelix088-spec/proxmox-vm-portal/contents/deploy/scripts/bootstrap-debian.sh?ref=v0.18.3" \
  --output "$bootstrap" && \
bash -n "$bootstrap" && \
sudo --preserve-env=PORTAL_GITHUB_TOKEN,PORTAL_GITHUB_USERNAME bash "$bootstrap"
result=$?
rm -f -- "$bootstrap"
unset PORTAL_GITHUB_TOKEN PORTAL_GITHUB_USERNAME
test "$result" -eq 0
```

L'installateur demande le domaine, l'adresse ACME, l'URL et l'identifiant du
token Proxmox, le destinataire `age`, puis les secrets Proxmox et administrateur
via des invites masquées. Docker conserve l'authentification GHCR du compte root
dans `/root/.docker/config.json` pour permettre les mises à jour ultérieures.
Révoquez le token temporaire après le test si vous ne souhaitez pas le conserver.

## Installation manuelle depuis les sources

```bash
sudo apt-get update && sudo apt-get install -y git
sudo git clone https://github.com/hugofelix088-spec/proxmox-vm-portal.git /opt/proxmox-vm-portal
cd /opt/proxmox-vm-portal
sudo cp .env.production.example .env.production
sudoedit .env.production
sudo bash deploy/scripts/install-debian.sh
```

Avant le lancement, renseigner au minimum `PORTAL_DOMAIN`, `ACME_EMAIL`,
`PVE_API_URL`, `PVE_TOKEN_ID`, `BACKUP_AGE_RECIPIENT` et
`BACKUP_DIRECTORY`. Les secrets sont générés ou demandés sans être inscrits dans
`.env.production`, puis conservés avec le mode 0600 sous `deploy/secrets/`. Le
jeton `portal_metrics_token` généré est destiné exclusivement au scraper
Prometheus ; ne le placez ni dans une URL ni dans la configuration Git.
Caddy obtient et renouvelle automatiquement le certificat public. Pour un nom
interne, installez une CA interne dans Caddy et dans les clients avant ouverture
aux utilisateurs ; ne désactivez jamais la vérification TLS.

Commandes courantes :

```bash
sudo deploy/scripts/compose.sh ps
sudo deploy/scripts/compose.sh logs --tail=200 api worker proxy
sudo deploy/scripts/compose.sh up -d --wait
```

## Keycloak interne optionnel

1. Définir `COMPOSE_PROFILES=keycloak`, `KEYCLOAK_DOMAIN`, les variables OIDC du
   portail et placer le même secret client dans
   `deploy/secrets/portal_oidc_client_secret`.
2. Relancer le script d'installation ; il active automatiquement le site Caddy.
3. Démarrer la stack, affecter les rôles du realm aux comptes, puis tester un
   compte administrateur et un compte utilisateur.
4. Ne mettre `PORTAL_LOCAL_AUTH_ENABLED=false` qu'après ce test. Conserver un
   processus de récupération documenté.

Le mot de passe administrateur initial de Keycloak se trouve dans le fichier
secret et doit être changé dès la première connexion. Pour LDAP, suivre
[`KEYCLOAK.md`](KEYCLOAK.md), préférer LDAPS, importer la CA d'entreprise et
tester la validation du certificat.

## Password Pusher interne optionnel

1. Définir `COMPOSE_PROFILES=pwpush` et `PWPUSH_DOMAIN`, puis relancer le script
   d'installation, qui active automatiquement le site Caddy.
2. Démarrer la stack et créer un compte dédié au portail dans Password Pusher.
3. Créer son jeton API v2, le placer dans
   `deploy/secrets/portal_pwpush_api_token`, définir
   `PORTAL_PWPUSH_URL=https://<PWPUSH_DOMAIN>`, puis redémarrer `api` et
   `worker`.
4. Après création du compte, désactiver les inscriptions si elles ne sont plus
   nécessaires.

Le volume SQLite est persistant et chiffré au niveau applicatif avec une clé
générée lors de l'installation. Perdre `pwpush_master_key` rend les pushes
existants illisibles. Le portail n'accepte pas d'URL Password Pusher choisie par
l'utilisateur.

## Durcissement après installation

- limiter 22/tcp aux réseaux d'administration et 80/443 aux réseaux clients ;
- appliquer les mises à jour Debian de sécurité et redémarrer après mise à jour
  du noyau ;
- retirer les comptes inutiles, interdire SSH root et privilégier les clés SSH ;
- tester les ACL du token Proxmox avec des opérations permises et interdites ;
- expédier les journaux Docker et l'audit applicatif vers un collecteur ;
- planifier `backup.sh`, copier les archives hors site et tester `restore.sh`.

Docker peut contourner certaines règles UFW lors de la publication de ports.
Vérifiez les règles nftables/iptables effectives, pas uniquement l'affichage UFW.
Ne montez jamais `/var/run/docker.sock` dans un conteneur du projet.

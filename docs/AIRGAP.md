# Déploiement autonome on-premise

Ce mode vise les réseaux hospitaliers, industriels et administratifs dans
lesquels la VM applicative ne doit contacter ni GitHub, ni GHCR, ni les dépôts
APT publics. Le jeton GitHub n'est utilisé que sur un poste de préparation
connecté et approuvé. Il n'est jamais copié dans le bundle ni sur la VM cible.

## Flux de confiance

1. Un poste Linux amd64 connecté récupère la release privée avec un PAT classic
   temporaire `repo` + `read:packages`.
2. Le poste vérifie le tag, le commit, la signature Sigstore de l'image et celle
   du manifeste, puis exporte chaque image dans une archive Docker étiquetée
   distincte avec les paquets Debian 13.
3. Avant de publier le bundle, la préparation supprime les images exportées,
   recharge chaque archive et contrôle son étiquette. L'identifiant `.Id`
   propre au moteur de publication est conservé pour l'audit, mais n'est pas
   utilisé comme preuve portable car Docker peut le recalculer lors d'un
   transfert entre ses magasins d'images OCI et classiques.
4. L'empreinte SHA-256 affichée est enregistrée dans la CMDB ou transmise par un
   canal distinct du support de transfert.
5. La VM Debian 13 vérifie cette empreinte, toutes les sommes internes et la
   signature du manifeste avec Cosign en `--network none`.
6. Compose utilise `pull_policy: never` pour chaque service et les étiquettes
   locales consignées dans le bundle. Une tentative de
   téléchargement externe échoue donc au lieu de contourner le bundle approuvé.

## Préparation sur le poste connecté

Le poste doit utiliser Linux amd64, Git et Docker. Depuis le tag de la release :

```bash
read -rsp "PAT GitHub du poste de préparation : " PORTAL_GITHUB_TOKEN && echo
export PORTAL_GITHUB_TOKEN
export PORTAL_GITHUB_USERNAME=hugofelix088-spec
export PORTAL_RELEASE_TAG=v0.19.7

deploy/scripts/prepare-offline-bundle.sh /srv/export-portal

unset PORTAL_GITHUB_TOKEN PORTAL_GITHUB_USERNAME
```

Le résultat contient une archive `.tar.gz` et son fichier `.sha256`. Le bundle
embarque les images du portail, PostgreSQL, Caddy, Keycloak, Password Pusher et
Cosign, ainsi que Docker Engine, Compose, `age`, OpenSSL et leurs dépendances
pour Debian 13 amd64.

La CI joint également ces deux fichiers directement à la release GitHub
publique. Un poste de transfert autorisé peut donc les télécharger sans
reconstruire le bundle et sans fournir de PAT à la VM cible.

Le fichier `.sha256` posé à côté de l'archive facilite le contrôle mais ne
constitue pas à lui seul un canal de confiance. Comparez sa valeur avec celle
enregistrée dans la CMDB avant extraction.

## Installation sur la VM isolée

Après transfert par le mécanisme approuvé de l'établissement :

```bash
sha256sum -c proxmox-vm-portal-offline-0.19.7-amd64.tar.gz.sha256
tar -xzf proxmox-vm-portal-offline-0.19.7-amd64.tar.gz
cd proxmox-vm-portal-offline-0.19.7-amd64
sudo bash install-offline.sh
```

Cette commande ne demande aucun identifiant GitHub et ne requiert aucune route
Internet. Par défaut, elle détecte la première IPv4 globale de la VM, démarre le
portail sur `https://IP_DE_LA_VM` avec la CA locale Caddy et génère les
identifiants initiaux ainsi qu'une identité `age`. Les chemins root-only à
consulter et à exporter sont affichés à la fin. Aucun paramètre Proxmox n'est
demandé pour ce premier démarrage.

Les secrets applicatifs restent dans un répertoire root-only et chaque fichier
monté dans le portail est lisible uniquement par l'UID non-root 10001. Cette
combinaison permet au conteneur durci de lire ses secrets sans les exposer aux
autres comptes de la VM.

Le frontal définit également l'adresse du portail comme SNI TLS par défaut.
Cela permet aux navigateurs et outils qui omettent le SNI lorsqu'ils contactent
directement une adresse IP de recevoir le certificat local correspondant.

Après la première connexion, remplacez le mot de passe généré depuis
l'administration des utilisateurs puis supprimez le fichier d'identifiants
root-only annoncé par l'installateur. Exportez également la clé privée `age`
vers le coffre de sauvegarde avant de la retirer de la VM.

Une fois connecté au portail, raccordez Proxmox séparément :

```bash
sudo /opt/proxmox-vm-portal/deploy/scripts/configure-proxmox.sh
```

Pour conserver l'ancien parcours entièrement paramétré avant démarrage, utilisez
`sudo bash install-offline.sh --production`. Pour imposer une IPv4 lorsque la VM
en possède plusieurs :

```bash
sudo PORTAL_INSTALL_IP=192.0.2.10 bash install-offline.sh
```

## DNS, PKI et services internes

Le mode hors ligne utilise par défaut la CA locale de Caddy pour le portail et
les profils Keycloak/Password Pusher. Exportez la racine située dans le volume
`caddy_data` par une procédure d'administration approuvée, puis distribuez-la
dans le magasin de confiance des postes clients. Pour un CHU, préférez remplacer
ce mécanisme par un certificat émis par la PKI d'entreprise avant ouverture aux
utilisateurs.

Le certificat racine local peut être exporté après installation avec :

```bash
sudo docker cp proxmox-vm-portal-proxy-1:/data/caddy/pki/authorities/local/root.crt \
  /root/proxmox-vm-portal-local-ca.crt
```

Cette CA permet de supprimer l'avertissement du navigateur pendant la phase de
test. Elle pourra être remplacée plus tard dans la configuration Caddy par le
certificat et la clé émis par la PKI de l'établissement.

Proxmox, LDAP/LDAPS, Keycloak, Password Pusher, DNS, NTP, SMTP, sauvegardes et
SIEM doivent utiliser exclusivement leurs adresses internes. L'accès sortant de
la VM peut ensuite être refusé par le pare-feu, à l'exception des flux internes
explicitement nécessaires.

## Mises à jour

Une mise à jour hors ligne doit être préparée comme un nouveau bundle, vérifiée
et transférée selon le même circuit. Après qualification du bundle sur une copie
de préproduction :

```bash
sha256sum -c proxmox-vm-portal-offline-NOUVELLE_VERSION-amd64.tar.gz.sha256
tar -xzf proxmox-vm-portal-offline-NOUVELLE_VERSION-amd64.tar.gz
cd proxmox-vm-portal-offline-NOUVELLE_VERSION-amd64
sudo bash install-offline.sh --update
```

La mise à jour refuse les versions identiques ou antérieures, vérifie la
signature sans réseau, charge les images, crée une sauvegarde chiffrée, conserve
la configuration et les secrets, puis applique les migrations. L'ancienne
source n'est supprimée qu'après réussite. En cas d'échec post-migration, suivez
la procédure de restauration plutôt que de relancer automatiquement l'ancien
code sur un schéma de base potentiellement plus récent.

Ne réactivez pas temporairement Internet sur la VM et n'utilisez pas
`deploy/scripts/update.sh`, réservé aux modes source et release connectés.

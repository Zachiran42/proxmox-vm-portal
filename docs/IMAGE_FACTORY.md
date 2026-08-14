# Usine d'images Debian

Le portail provisionne les VM automatiquement en clonant des templates
cloud-init approuvés. La recette `images/packer/debian-13.pkr.hcl` construit le
template Debian 13 depuis l'ISO netinst officielle, sans installation manuelle.

## Garanties de la recette

- Debian 13.6 et sa somme SHA-256 officielle sont épinglés dans le code ;
- Packer utilise exactement le plugin Proxmox `1.2.4` et refuse TLS non vérifié ;
- le token PVE appartient obligatoirement à un compte non-root ;
- le mot de passe Packer est aléatoire, généré en mémoire à chaque construction
  et n'est ni affiché ni écrit sur disque ;
- root ne reçoit aucun mot de passe et sa connexion SSH est désactivée ;
- le compte Packer perd son sudo, est verrouillé, expire et utilise `nologin`
  avant la conversion en template ;
- les identifiants machine, les clés hôte SSH, les journaux et l'état cloud-init
  sont nettoyés avant clonage ;
- QEMU Guest Agent et cloud-init sont installés et activés ;
- le firewall Proxmox est activé sur l'interface du template.

L'ISO `debian-13.6.0-amd64-netinst.iso` doit être présente dans le stockage ISO
indiqué par `PACKER_PVE_ISO_STORAGE`. La construction s'arrête si son contenu ne
correspond pas à la somme officielle attendue.

## Prérequis et ACL

Installer Packer et OpenSSL sur une machine d'administration isolée. Le compte
de service PVE doit disposer, seulement sur le pool, le nœud et les deux
stockages de construction, des droits requis par le builder ISO Proxmox :
allocation/configuration de VM, allocation d'espace, audit du datastore et
utilisation du pool. Avec Proxmox VE 9, la découverte de l'adresse IP par QEMU
Guest Agent requiert aussi `VM.GuestAgent.Audit` sur les VM de construction. Ne
réutilisez pas le token du portail et n'accordez jamais le rôle Administrateur
global.

Le serveur HTTP temporaire de Packer doit être joignable depuis le VLAN de
construction. Ce VLAN ne doit pas permettre d'atteindre le réseau de gestion
hors des flux strictement nécessaires. Le fichier Preseed transporte uniquement
le hash du mot de passe éphémère, jamais sa valeur claire.

## Construire le template

Exporter les valeurs dans le shell d'administration, sans les placer dans un
fichier versionné :

```bash
export PACKER_PVE_URL='https://pve.example.internal:8006/api2/json'
export PACKER_PVE_USERNAME='packer@pve!image-factory'
export PACKER_PVE_TOKEN='valeur-secrete-du-token'
export PACKER_PVE_NODE='pve-a'
export PACKER_PVE_POOL='image-factory'
export PACKER_PVE_ISO_STORAGE='local'
export PACKER_PVE_VM_STORAGE='local-lvm'

# Facultatif : vmbr0 et 9130 par défaut.
export PACKER_PVE_BRIDGE='vmbr0'
export PACKER_TEMPLATE_VMID='9130'

./images/packer/build.sh
unset PACKER_PVE_TOKEN
```

Packer valide la recette, installe Debian, applique le durcissement et convertit
la VM en template. En cas d'échec, supprimer manuellement la VM de construction
après avoir contrôlé son VMID ; le script ne supprime jamais une ressource PVE.

## Contrôler et publier

Une construction réussie crée `images/packer/promotion.json`, ignoré par Git.
Le manifeste contient seulement l'identité du template, l'ISO, sa somme et les
versions de recette. Valider ce fichier puis produire la charge JSON :

```bash
python3 portal/image_manifest.py validate images/packer/promotion.json \
  > /tmp/debian-13-profile.json
```

Avant publication, cloner manuellement une VM de recette et vérifier :

1. la régénération des clés SSH et de l'identifiant machine ;
2. la création du compte demandé, son appartenance à `sudo` et l'expiration du
   mot de passe initial ;
3. le refus de `root` en SSH ;
4. le fonctionnement de QEMU Guest Agent et du réseau cloud-init ;
5. les mises à jour de sécurité et l'absence du compte Packer utilisable.

Connecté en administrateur, envoyer ensuite la charge validée à
`POST /api/admin/image-profiles` avec le jeton CSRF de la session. Le portail
interroge immédiatement Proxmox et refuse le profil si le VMID n'est pas un
template. Le worker refait cette vérification avant chaque clonage.

Conserver le manifeste avec les preuves de recette dans un stockage d'audit
restreint, pas dans Git. Reconstruire un nouveau VMID après chaque changement
d'ISO ou de recette, qualifier le clone, publier le nouveau profil puis
désactiver l'ancien profil. Ne remplacez jamais en place un template déjà publié.

# Compte invité et Password Pusher

## Garanties du portail

Un profil `cloud_init` clone un template Proxmox approuvé. L'utilisateur choisit
son mot de passe SSH dans l'assistant. Le portail configure `ciuser` et
`cipassword` par l'API TLS Proxmox. Le mot de passe clair n'est ni écrit en base,
ni placé dans l'audit, ni retourné par l'API du portail.

Le secret est chiffré avec la clé applicative pendant son passage dans la file
asynchrone, puis le chiffré est effacé dès que Proxmox accepte la configuration
cloud-init. Une rotation de la clé applicative invalide volontairement tout
secret encore en attente. L'administrateur choisit une longueur minimale de 1 à
256 caractères ; aucune classe de caractères n'est imposée.

## Préparer un template cloud-init

La recette Packer versionnée transforme automatiquement l'ISO Debian en template
cloud-init. Sa construction, son durcissement et sa promotion sont décrits dans
[`IMAGE_FACTORY.md`](IMAGE_FACTORY.md). Un administrateur doit toujours tester
un clone avant de publier son profil :

1. partir d'une image cloud officielle dont la somme est vérifiée ;
2. installer et activer cloud-init et le QEMU Guest Agent ;
3. ajouter le lecteur cloud-init recommandé par Proxmox puis convertir la VM en
   template ;
4. configurer cloud-init avec `disable_root: true`, désactiver
   `PermitRootLogin` dans OpenSSH et conserver un utilisateur par défaut membre
   de `sudo` ;
5. imposer le changement du mot de passe initial avec `chpasswd.expire: true` ;
6. vérifier sur un clone de recette que `sudo -l` fonctionne, que root ne peut
   pas se connecter en SSH et que le mot de passe doit être changé ;
7. créer seulement ensuite le profil administrateur :

```json
{
  "slug": "debian-13-cloud",
  "label": "Debian 13 Cloud",
  "description": "Template durci et validé",
  "source_type": "cloud_init",
  "template_node": "pve-03",
  "template_vmid": 9130
}
```

La demande utilisateur correspondante contient par exemple
`"guest_username": "hugo"`. `root` et `admin` sont refusés.

## Reprise après incident

Si la configuration Proxmox est temporairement indisponible, le worker réessaie
au maximum cinq fois avec le même secret choisi. Si le démarrage Proxmox est
ambigu, le travail passe en `attention` après avoir effacé le chiffré. Avant
toute action manuelle, vérifiez le VMID et l'état réel de la VM dans Proxmox.

Le token PVE doit être limité aux templates, nœuds et pools nécessaires, avec
uniquement les droits de clonage, configuration cloud-init, redimensionnement et
démarrage requis. Testez ces ACL avec un compte de service non-root.

# Compte invité et Password Pusher

## Garanties du portail

Un profil `cloud_init` clone un template Proxmox approuvé. Le portail génère un
mot de passe avec un générateur cryptographique, configure `ciuser` et
`cipassword` par l'API TLS Proxmox, puis l'envoie à l'API JSON v2 de Password
Pusher. Le mot de passe clair n'est ni écrit en base, ni placé dans l'audit, ni
retourné par l'API du portail.

L'intégration cible l'API v2 de Password Pusher OSS 2.9 ou ultérieure. Cette API
étant encore annoncée comme bêta par l'éditeur, testez l'intégration avant toute
mise à niveau de Password Pusher.

Seuls le propriétaire de la VM et sa session authentifiée peuvent obtenir le
lien expirant. Les administrateurs et opérateurs qui ne possèdent pas la VM ne
reçoivent que l'état du travail. Les réponses sont servies avec
`Cache-Control: no-store`.

L'URL Password Pusher est une configuration d'exploitation : elle peut viser
une instance interne auto-hébergée ou un service externe. Elle n'est jamais
fournie par l'utilisateur. HTTPS, la vérification du certificat et l'API token
sont obligatoires. `PORTAL_PWPUSH_CA_BUNDLE` permet d'utiliser une CA interne.

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

Si Password Pusher est indisponible, le worker réessaie au maximum cinq fois et
génère un nouveau mot de passe à chaque essai. Si le démarrage Proxmox est
ambigu, le travail passe en `attention` sans perdre le lien déjà créé. Avant
toute action manuelle, vérifiez le VMID et l'état réel de la VM dans Proxmox.

Le token PVE doit être limité aux templates, nœuds et pools nécessaires, avec
uniquement les droits de clonage, configuration cloud-init, redimensionnement et
démarrage requis. Testez ces ACL avec un compte de service non-root.

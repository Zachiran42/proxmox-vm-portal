# Préparer la supervision Zabbix

## Deux niveaux complémentaires

La supervision doit séparer le cluster de ses systèmes invités :

1. **Proxmox VE** : utiliser le template officiel `Proxmox VE by HTTP` avec un
   compte et un token PVE dédiés à Zabbix. Ce token est distinct du token du
   portail et possède seulement `Sys.Audit` sur `/`, `Datastore.Audit` sur
   `/storage` et `VM.Audit` sur `/vms`.
2. **Chaque VM Debian** : installer Zabbix Agent 2 dans le template
   `debian-13-cloudinit`, puis personnaliser son identité au premier démarrage.
   L'agent surveille l'OS, les services, les fichiers et les métriques que l'API
   Proxmox ne voit pas.

Le template Proxmox offre une vue de l'hyperviseur, mais ne remplace pas l'agent
dans les VM. Le token du portail ne doit jamais être réutilisé pour Zabbix.

## Architecture recommandée en CHU

Placez un Zabbix Proxy dans chaque zone serveur qui ne doit pas accepter de flux
direct depuis le serveur central. Les agents utilisent les contrôles actifs :
ils ouvrent eux-mêmes une connexion vers le proxy défini par `ServerActive`.
Cette architecture réduit les ouvertures entrantes entre VLAN et permet au proxy
de tamponner les données lors d'une coupure avec le serveur.

Chiffrez les échanges agent/proxy avec un certificat propre à la VM ou une PSK
propre à la VM. Une PSK commune à tout le parc augmenterait fortement l'impact
d'une compromission. La PSK est un secret : elle ne doit figurer ni dans Git,
ni dans les logs, ni dans les métadonnées publiques de cloud-init.

## Préparation du template Debian

La prochaine recette d'image pourra ajouter `zabbix-agent2` sans l'activer tant
que l'intégration n'est pas configurée. Au clonage, cloud-init fournira :

- un `Hostname` unique, identique au nom géré par le portail ;
- l'adresse du serveur ou du proxy dans `ServerActive` ;
- des métadonnées non sensibles comme `portal`, l'environnement et le VLAN ;
- le matériel TLS propre à la VM depuis un gestionnaire de secrets interne.

L'agent est ensuite activé seulement quand l'hôte correspondant existe dans
Zabbix. Pour un premier POC isolé, l'auto-enregistrement actif sécurisé par PSK
est possible. Pour la version finale du portail, l'API Zabbix donne davantage de
contrôle et permet une réconciliation explicite.

## Intégration future dans le portail

La cible est une carte `Administration > Intégrations d'infrastructure > Zabbix`
avec les paramètres suivants : URL HTTPS, token API, CA interne, groupe d'hôtes,
template Linux, proxy ou groupe de proxies et activation par défaut. Le token
Zabbix appartient à un compte de service au rôle restreint aux groupes gérés par
le portail.

Après qu'une VM est démarrée et que son IPv4 est connue, un travail asynchrone et
idempotent doit :

1. rechercher l'hôte par un identifiant stable du portail ;
2. appeler `host.create` ou `host.update` avec l'IP, le groupe, le template, le
   proxy, les tags et l'inventaire ;
3. mémoriser uniquement le `hostid` Zabbix et l'état de synchronisation ;
4. réessayer sans bloquer le provisionnement si Zabbix est indisponible ;
5. désactiver puis supprimer l'hôte selon la politique de conservation lorsque
   la VM est supprimée.

Tags conseillés : `portal_vm_id`, `owner`, `pve_node`, `pve_vmid`, `vlan`,
`environment` et `expires_at`. Le propriétaire ne voit que l'état de supervision
de sa VM ; les paramètres et secrets Zabbix restent réservés aux administrateurs.

## Ordre de réalisation

1. Déployer Zabbix Server et un proxy de test.
2. Superviser le cluster avec le template officiel Proxmox et son token dédié.
3. Tester Zabbix Agent 2 sur un clone jetable du template Debian.
4. Choisir certificats ou PSK uniques et valider les flux pare-feu.
5. Ajouter le client API, les migrations, les travaux de réconciliation et la
   carte d'administration au portail.
6. Qualifier création, changement d'IP, indisponibilité Zabbix et suppression.

Références officielles :

- [template Proxmox VE by HTTP](https://www.zabbix.com/integrations/proxmox) ;
- [contrôles actifs et passifs](https://www.zabbix.com/documentation/current/en/manual/appendix/items/activepassive) ;
- [API `host.create`](https://www.zabbix.com/documentation/current/en/manual/api/reference/host/create) ;
- [chiffrement TLS de Zabbix](https://www.zabbix.com/documentation/current/en/manual/encryption) ;
- [auto-enregistrement des agents actifs](https://www.zabbix.com/documentation/7.4/en/manual/discovery/auto_registration).

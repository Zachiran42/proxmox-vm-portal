# Réseaux, VLAN et NetBox

Le portail propose aux utilisateurs uniquement les profils réseau activés par un
administrateur. Un profil contient le CIDR IPv4, la passerelle, les DNS, le bridge
Proxmox et, si nécessaire, le tag VLAN 802.1Q.

Exemple CHU : `VLAN serveurs CHU`, `10.10.12.0/24`, passerelle
`10.10.12.254`, DNS internes, bridge `vmbr0` et tag VLAN `12`.

Le bridge doit exister sur tous les nœuds ciblés et transporter le VLAN indiqué.
Le token Proxmox du portail doit conserver `VM.Config.Network` et `SDN.Use` sur
le bridge concerné.

## Configurer NetBox depuis le portail

NetBox reste optionnel. Sans NetBox, le portail empêche les doublons présents
dans sa propre base. Avec NetBox, il devient la source de vérité partagée avec
les autres outils d'infrastructure.

Créez un compte de service NetBox limité à la lecture des préfixes IPAM et à
l'ajout, la modification et la suppression des adresses IP IPAM. Dans
`Administration > Intégrations d'infrastructure`, renseignez ensuite :

- l'URL HTTPS de NetBox ;
- son token API ;
- la CA interne au format PEM si elle n'est pas reconnue par Debian ;
- l'activation de l'intégration.

Le portail teste la connexion avant l'enregistrement. Le token est chiffré en
base avec une clé dérivée du secret de session persistant ; il n'est jamais
renvoyé au navigateur ni inscrit dans l'audit. La commande suivante reste un
mode de secours pour une configuration hors interface :

```bash
cd /opt/proxmox-vm-portal
sudo bash deploy/scripts/configure-netbox.sh
```

Le script exige HTTPS, vérifie la CA et le token, stocke le token dans un secret
Docker en lecture seule, puis redémarre uniquement l'API et le worker. Cette
configuration sert aussi de solution de repli si la configuration Web est
désactivée. Renseignez ensuite l'identifiant numérique du préfixe NetBox dans le
profil réseau. Le portail vérifie que le CIDR NetBox correspond exactement au
CIDR administré.

## Plage automatique d'un VLAN

Un administrateur peut activer, profil par profil, la saisie manuelle, l'IP fixe
automatique, ou les deux. Pour l'attribution automatique, il définit une première
et une dernière adresse ainsi qu'une liste d'exclusions. La passerelle, les
adresses réseau/diffusion, les exclusions et les allocations actives du portail
ne sont jamais proposées.

Lorsqu'une adresse paraît libre localement mais existe déjà dans NetBox, le
worker passe automatiquement à l'adresse suivante. Si toute la plage est
occupée, la demande s'arrête avec le code `ip_pool_exhausted` sans créer de VM.

## Cycle de vie d'une adresse fixe

1. L'utilisateur sélectionne un profil réseau et saisit une IP autorisée, ou
   demande une IP automatique dans la plage administrée.
2. Le portail vérifie préfixe, passerelle, DNS et réservations locales.
3. Le worker crée atomiquement l'adresse dans NetBox à l'état `reserved`.
4. La VM est clonée, puis bridge, tag VLAN et cloud-init sont configurés.
5. Après démarrage confirmé, l'adresse passe à l'état `active` dans NetBox.
6. Après suppression Proxmox confirmée, l'objet IP NetBox est supprimé.

Une indisponibilité NetBox est réessayée sans rejouer l'opération Proxmox. Un
résultat Proxmox ambigu conserve la réservation pour prévenir une double
attribution.

Documentation officielle :

- <https://netboxlabs.com/docs/netbox/v4.4/integrations/rest-api/>
- <https://netboxlabs.com/docs/netbox/v4.4/models/ipam/ipaddress/>
- <https://netboxlabs.com/docs/netbox/models/ipam/iprange/>

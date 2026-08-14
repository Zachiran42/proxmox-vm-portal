# Réseaux, VLAN et NetBox

Le portail propose aux utilisateurs uniquement les profils réseau activés par un
administrateur. Un profil contient le CIDR IPv4, la passerelle, les DNS, le bridge
Proxmox et, si nécessaire, le tag VLAN 802.1Q.

Exemple CHU : `VLAN serveurs CHU`, `10.10.12.0/24`, passerelle
`10.10.12.254`, DNS internes, bridge `vmbr0` et tag VLAN `12`.

Le bridge doit exister sur tous les nœuds ciblés et transporter le VLAN indiqué.
Le token Proxmox du portail doit conserver `VM.Config.Network` et `SDN.Use` sur
le bridge concerné.

## Activer NetBox

NetBox reste optionnel. Sans NetBox, le portail empêche les doublons présents
dans sa propre base. Avec NetBox, il devient la source de vérité partagée avec
les autres outils d'infrastructure.

Créez un compte de service NetBox limité à la lecture des préfixes IPAM et à
l'ajout, la modification et la suppression des adresses IP IPAM. Puis lancez :

```bash
cd /opt/proxmox-vm-portal
sudo bash deploy/scripts/configure-netbox.sh
```

Le script exige HTTPS, vérifie la CA et le token, stocke le token dans un secret
Docker en lecture seule, puis redémarre uniquement l'API et le worker. Renseignez
ensuite l'identifiant numérique du préfixe NetBox dans le profil réseau. Le
portail vérifie que le CIDR NetBox correspond exactement au CIDR administré.

## Cycle de vie d'une adresse fixe

1. L'utilisateur sélectionne un profil réseau et saisit une IP du CIDR proposé.
2. Le portail vérifie préfixe, passerelle, DNS et réservations locales.
3. Le worker crée atomiquement l'adresse dans NetBox à l'état `reserved`.
4. La VM est clonée, puis bridge, tag VLAN et cloud-init sont configurés.
5. Après démarrage confirmé, l'adresse passe à l'état `active` dans NetBox.
6. Après suppression Proxmox confirmée, l'objet IP NetBox est supprimé.

Une indisponibilité NetBox est réessayée sans rejouer l'opération Proxmox. Un
résultat Proxmox ambigu conserve la réservation pour prévenir une double
attribution.

Documentation officielle :

- <https://netboxlabs.com/docs/netbox/en/stable/integrations/rest-api/>
- <https://netboxlabs.com/docs/netbox/en/stable/models/ipam/ipaddress/>

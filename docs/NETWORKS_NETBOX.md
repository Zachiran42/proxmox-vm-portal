# Réseaux, VLAN et NetBox

Le portail propose aux utilisateurs uniquement les profils réseau activés par un
administrateur. Un profil contient le CIDR IPv4, la passerelle, les DNS, le bridge
Proxmox et, si nécessaire, le tag VLAN 802.1Q.

Chaque profil porte aussi une politique de connectivité explicite :

- **bac à sable** : mode initial normal de toute VM, avec `net0` actif, `DROP`
  en entrée et en sortie et uniquement les services internes autorisés par le
  profil ;
- **isolée** : quarantaine renforcée qui conserve `DROP` et déconnecte aussi
  `net0` ;
- **interne contrôlé** et **Internet autorisé** : intentions de connectivité qui
  restent initialement en bac à sable jusqu'à une approbation administrative ;
- **ouverture sur ticket** : la VM naît isolée comme dans le premier mode. Une
  URL HTTPS de demande de flux doit être configurée dans les paramètres avant
  qu'un utilisateur puisse sélectionner le profil.

La sortie du bac à sable ne peut pas être appliquée par l'utilisateur. Il
dépose une demande motivée ; seul un administrateur peut l'approuver ou la
refuser depuis l'inventaire. La décision et sa justification sont auditées. Les
règles détaillées et le catalogue logiciel hors Internet sont documentés dans
[`SANDBOX.md`](SANDBOX.md).

Le champ **Portée autorisée** permet à l'administrateur d'afficher une consigne
concrète, par exemple « réseau de test, sans accès au SI de production ». Ce
texte est informatif : les restrictions doivent également être matérialisées
sur le pare-feu, le VLAN ou la microsegmentation du CHU.

Exemple CHU : `VLAN serveurs CHU`, `10.10.12.0/24`, passerelle
`10.10.12.254`, DNS internes, bridge `vmbr0` et tag VLAN `12`.

Le bridge doit exister sur tous les nœuds ciblés et transporter le VLAN indiqué.
Le token Proxmox du portail doit conserver `VM.Config.Network` et `SDN.Use` sur
le bridge concerné. Les profils isolés nécessitent également les droits de
pare-feu documentés dans `docs/VM_MAINTENANCE.md` et l'activation du pare-feu
Proxmox au niveau datacenter.

## Procédure d'ouverture sur ticket

1. L'administrateur configure l'URL HTTPS du formulaire GLPI dans
   **Administration > Paramètres de provisionnement**.
2. Il crée un profil avec la politique **Sur ticket** et décrit la portée
   attendue.
3. La VM est provisionnée et reste isolée, même si elle obtient une adresse IP.
4. L'utilisateur ouvre GLPI depuis le détail de sa VM, crée son ticket puis
   reporte sa référence, la durée et les flux attendus dans le portail.
5. Après validation externe et mise en place des règles amont, un administrateur
   prend la décision depuis la console du portail. L'ouverture approuvée expire
   automatiquement et la VM retourne alors en sandbox.

L'ouverture et la fermeture sont auditées. Le portail ne considère jamais la
simple création d'un ticket comme une autorisation technique.

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

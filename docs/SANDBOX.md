# Bac à sable réseau et logiciels hors ligne

Toute nouvelle VM est confinée avant d'être déclarée prête. Le portail active le
pare-feu de la VM Proxmox, conserve le lien `net0` actif et applique `DROP` en
entrée et en sortie. Les seules règles `ACCEPT` sont dérivées du profil réseau
approuvé.

Le mode `isolated` reste une quarantaine d'urgence : il applique également
`DROP`, mais positionne `link_down=1`. Un profil explicitement configuré comme
`isolated` ou `ticket_required` démarre donc sans connectivité. Tous les autres
profils démarrent en `sandbox`, même si leur ancienne portée déclarative était
`internal` ou `internet`.

## Services autorisables

L'administration du portail permet de définir, pour chaque réseau/VLAN :

- les CIDR autorisés à entrer en SSH sur TCP/22 ;
- les DNS internes sur UDP et TCP/53 ;
- les NTP internes sur UDP/123 ;
- les miroirs APT internes sur TCP/443 ;
- les registres OCI internes sur TCP/443 ;
- les serveurs Zabbix sur TCP/10050 et TCP/10051.

DHCP utilise uniquement UDP/67 et UDP/68. Aucun `ACCEPT` général vers
`0.0.0.0/0:443` n'est créé. Le VLAN ou la VRF de test doit en complément ne
posséder aucune route vers les réseaux de production. Le pare-feu Proxmox est
une seconde barrière, pas un remplacement de cette segmentation réseau.

Chaque règle créée par le portail porte un commentaire `portal-sandbox:*`. Une
nouvelle application supprime uniquement les règles portant ce préfixe et ne
touche pas aux règles ajoutées par les équipes infrastructure. La révision du
profil appliqué est mémorisée sur la VM et visible dans l'inventaire.

## Sortie du bac à sable

L'utilisateur ne dispose d'aucun endpoint permettant de passer directement en
mode normal. Depuis les détails de sa VM, il ouvre d'abord le formulaire GLPI
configuré par l'administrateur, puis renseigne dans le portail la référence du
ticket, la durée souhaitée (1 à 720 heures) et les flux attendus. Cette demande
apparaît dans le rapport MCO et notifie les administrateurs.

Seul un administrateur peut l'approuver ou la refuser. Une approbation applique
temporairement la politique `normal` dans Proxmox et inscrit le ticket GLPI, la
décision, sa justification, son auteur et l'échéance dans le journal d'audit.
À l'échéance, le worker réapplique automatiquement les règles sandbox et notifie
l'utilisateur. L'administrateur peut toujours placer la VM en quarantaine
totale, puis la remettre en sandbox.

Les ouvertures DNS, HTTP(S) ou autres restent traitées par le firewall et les
ingénieurs réseau du CHU. Le portail ne crée pas automatiquement ces flux dans
les équipements réseau.

## Catalogue logiciel sans Internet

Les administrateurs publient des modules selon trois modes :

- `preinstalled` : le paquet doit déjà être présent dans le template ;
- `apt` : le paquet est installé depuis les sources APT configurées dans le
  template ;
- `container` : l'image OCI est vérifiée localement puis téléchargée depuis le
  registre interne si elle manque.

Les noms de paquet et références OCI sont validés côté serveur. Les références
de conteneur doivent inclure un registre et un tag ou digest. Le processus est
exécuté via QEMU Guest Agent et la VM n'est déclarée prête qu'après succès.

Pour garantir l'absence d'accès Internet :

1. configurer dans le template uniquement le miroir APT interne et sa clé ;
2. installer la CA interne du registre OCI ;
3. précharger Docker dans le template ou publier ses paquets dans le miroir ;
4. importer et qualifier les images OCI dans le registre interne ;
5. autoriser seulement les IP de ces services dans le profil sandbox ;
6. vérifier l'absence de route du VLAN de test vers la production et Internet.

Les dépôts ne doivent pas être hébergés sur les hyperviseurs Proxmox. Utiliser
des VM de service dédiées et sauvegardées.

## Droits Proxmox

Le token du portail doit disposer de la lecture du pare-feu Datacenter et des
droits nécessaires à la configuration réseau/pare-feu des VM qu'il gère,
notamment `VM.Config.Network`. Il ne doit jamais être un token `root@pam`.

Avant la production, valider sur un VLAN de recette : DHCP, DNS, NTP, SSH depuis
le bastion, APT, registre OCI, Zabbix, refus inter-VM, refus vers la production,
refus Internet et journalisation SIEM.

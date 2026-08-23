# Maintenance APT et isolement réseau

Le portail permet aux administrateurs d'analyser et de mettre à jour les VM de
test créées depuis un template Cloud-Init. Les commandes sont exécutées hors
réseau d'administration par QEMU Guest Agent : aucun accès SSH du portail vers
la VM et aucune clé SSH centrale ne sont nécessaires.

## Opérations proposées

- **Analyser APT** : exécute `apt-get update`, inventorie les paquets pouvant
  être mis à jour et détecte `/run/reboot-required`.
- **Mettre à jour** : utilise `apt-get upgrade` en mode non interactif, conserve
  les fichiers de configuration locaux et ne redémarre jamais la VM.
- **Isoler** : applique au niveau du pare-feu Proxmox `DROP` en entrée et en
  sortie, puis place le lien virtuel `net0` à l'état déconnecté. Le LAN,
  Internet, IPv4 et IPv6 sont ainsi coupés, y compris pour une connexion déjà
  établie.
- **Journal réseau** : affiche les paquets refusés par le pare-feu Proxmox. Il
  n'inspecte ni les fichiers, ni les processus, ni le contenu des échanges dans
  la VM.

Le portail ne propose ni `full-upgrade`, ni `autoremove`, ni ajout de dépôt APT.
Les commandes sont constantes dans le code : aucun argument de shell fourni par
un utilisateur n'est accepté. Une VM isolée ne peut pas joindre les dépôts APT ;
le portail refuse donc sa maintenance avant sa reconnexion explicite.

## Frontière de sécurité Proxmox

L'isolement n'est considéré comme réussi que lorsque :

1. le pare-feu du Datacenter Proxmox est activé ;
2. l'interface `net0` de la VM contient `firewall=1` ;
3. Proxmox confirme `enable=1`, `policy_in=DROP` et `policy_out=DROP` sur la VM ;
4. Proxmox confirme `link_down=1` sur `net0`.

La base du portail n'enregistre la nouvelle politique qu'après ces quatre
contrôles. En cas d'échec partiel, les mesures déjà appliquées restent dans
l'état le plus restrictif et l'administrateur reçoit une erreur. Le portail
n'active volontairement pas le pare-feu global : cette action peut couper
l'administration du cluster et doit être préparée avec les règles de management.

Avant le test, conserver une session Proxmox ouverte, autoriser les réseaux de
management puis activer le pare-feu Datacenter :

```bash
pvesh set /cluster/firewall/options --enable 1
pve-firewall status
qm config VMID | grep '^net0:'
```

Les templates construits par le projet activent déjà `firewall=1` sur `net0`.

## Droits du token portail

Les fonctions nécessitent, sur les seules VM de test gérées par le portail :

- `VM.GuestAgent.Unrestricted` : inventaire et mise à jour APT ;
- `VM.Config.Network` : politique pare-feu de la VM ;
- `VM.Console` : lecture du journal pare-feu ;
- `VM.Audit` : lecture de la configuration et des options.

Exemple pour un environnement de test où `/vms` est entièrement dans le
périmètre du portail :

```bash
pveum role add PortalMaintenance \
  --privs "VM.Audit VM.Console VM.Config.Network VM.GuestAgent.Unrestricted" \
  2>/dev/null ||
pveum role modify PortalMaintenance \
  --privs "VM.Audit VM.Console VM.Config.Network VM.GuestAgent.Unrestricted"

pveum acl modify /vms --user portal@pve --role PortalMaintenance
pveum acl modify /vms --token 'portal@pve!provisioning' --role PortalMaintenance
```

`VM.GuestAgent.Unrestricted` est puissant. Utiliser un token dédié, restreint
aux VM du portail, sans droit sur les hôtes ni sur les autres VM du cluster.

## Journal et historique

Le journal affiché provient de `/var/log/pve-firewall.log` via l'API Proxmox. Il
contient les métadonnées des paquets refusés (direction, adresses, protocole et
ports selon le paquet), mais pas leur charge utile. Proxmox gère sa rotation ;
le portail ne duplique pas ces données sensibles dans PostgreSQL.

Lorsque la VM est totalement isolée, le lien virtuel est déconnecté : aucune
nouvelle tentative n'atteint alors le pare-feu de l'hyperviseur. Le journal
montre donc surtout les refus observés avant la coupure totale ou en mode réseau
normal protégé par les règles Proxmox.

Pour conserver tous les flux autorisés sur une longue durée, utiliser plus tard
une collecte dédiée (IPFIX/NetFlow ou IDS sur le réseau de test). Journaliser
chaque paquet accepté dans le portail créerait un volume excessif et une nouvelle
base de données sensible.

Le portail conserve pour chaque maintenance l'administrateur demandeur,
l'action, les horodatages, les noms des paquets disponibles, les compteurs
avant/après, le besoin de redémarrage et un code d'erreur normalisé. La sortie
APT complète n'est pas retournée par l'API.

## Demande d'ouverture de flux

L'administrateur peut saisir dans **Administration > Paramètres de
provisionnement** l'URL HTTPS du formulaire GLPI de l'établissement. Lorsque la
valeur est renseignée, les détails de chaque VM affichent le bouton **Ouvrir le
formulaire GLPI**. Le lien s'ouvre dans un nouvel onglet avec la protection
`noopener,noreferrer`. Après création du ticket, l'utilisateur reporte sa
référence, la durée demandée et les flux attendus dans le portail.

La création du ticket ne modifie jamais le pare-feu. Seule l'approbation d'un
administrateur ouvre temporairement la VM ; le worker la replace automatiquement
en sandbox à l'échéance. Une valeur vide interdit l'enregistrement d'une demande.

# File de provisionnement

`POST /api/vms` réserve le quota et crée atomiquement un travail PostgreSQL. La
requête HTTP ne contacte pas Proxmox. Un ou plusieurs workers consomment ensuite
la file avec `FOR UPDATE SKIP LOCKED` :

```bash
flask --app 'portal:create_app' worker
```

Utilisez `--once` pour traiter une seule transition, notamment dans un test ou
une tâche planifiée. En production, exécutez le worker comme un service distinct
du serveur web et redémarrez-le automatiquement après un échec.

## États

- `queued` : en attente d'un worker ;
- `validating` : validation du profil et présence de l'ISO ;
- `submitting` : création sur le point d'être envoyée à Proxmox ;
- `submitted` ou `polling` : UPID reçu et suivi en cours ;
- `succeeded` : tâche Proxmox terminée avec `OK` ;
- `failed` : refus explicite ou erreur terminale, quota libéré ;
- `attention` : résultat ambigu, intervention d'un opérateur nécessaire.

Une erreur réseau pendant la consultation de l'inventaire ou le suivi d'un UPID
est réessayée. En revanche, une coupure pendant l'envoi de la création peut
signifier que Proxmox a accepté la VM sans que le portail reçoive le UPID. Le
travail passe alors en `attention` et n'est jamais soumis une seconde fois.

Pour un profil cloud-init, le premier UPID suit le clone du template. Le worker
déchiffre ensuite le mot de passe choisi, configure le compte invité puis efface
le chiffré avant de suivre le second UPID de démarrage. Une erreur de transport
est rejouée avec le même secret afin de garder le choix de l'utilisateur.

## Cycle de vie

Les opérations `start`, `stop`, `reboot` et `delete` utilisent la table
`vm_operations`. Un index unique partiel interdit deux opérations actives sur
une même VM. Avant chaque soumission, le worker lit l'état réel de la VM dans
Proxmox et réconcilie la base locale. Un démarrage déjà réalisé hors portail est
donc traité comme une réussite idempotente. Une suppression est refusée avec un
message explicite tant que Proxmox indique que la VM tourne. Le worker suit
ensuite le `UPID` comme pour le provisionnement. Un crash pendant la soumission
place l’opération en revue manuelle afin de ne jamais la rejouer aveuglément.

Les actions Proxmox `POST` sans paramètre envoient un objet JSON vide (`{}`).
Cela évite avec Proxmox VE 9 une réponse HTTP 500 lors du décodage. À l'inverse,
la suppression `DELETE` est envoyée sans corps et sans `Content-Type`, car PVE 9
refuse explicitement tout contenu sur cette méthode.

Une suppression réussie passe l’allocation à `deleted`, efface le lien de remise
d’accès restant et libère alors seulement CPU, RAM, disque et compteur de VM.
La requête standard détruit la VM et ses disques référencés. Le portail n'active
pas `purge` ni `destroy-unreferenced-disks`, afin de ne jamais étendre la
suppression aux configurations ou volumes annexes.

Les demandes échouées et les VM supprimées peuvent être archivées par leur
propriétaire. L'archivage masque uniquement la carte de la liste principale :
il ne supprime ni l'allocation, ni le travail, ni les opérations, ni les
événements d'audit. La vue « Archives » permet de les consulter et de les
restaurer. Une VM active ou encore en provisionnement ne peut pas être archivée.

## Exploitation

Les états `submitting` et `attention` doivent déclencher une alerte. Avant toute
correction manuelle, recherchez la VM par son nom et son propriétaire dans
Proxmox et consultez le journal d'audit du portail. Ne remettez pas aveuglément
un travail `attention` dans la file.

La vue Administration affiche les heartbeats des workers, la connectivité
Proxmox, la profondeur de file et les travaux en `attention`. La reprise du
suivi est disponible seulement si le portail possède déjà le nœud et l’UPID ;
elle ne soumet donc aucune nouvelle action. Une clôture en échec demande le nom
exact de la VM et doit être utilisée uniquement après avoir vérifié son absence
dans Proxmox. Ces deux décisions sont inscrites dans le journal d’audit.

`PORTAL_JOB_POLL_SECONDS` règle l'intervalle de suivi (1 à 300 secondes) et
`PORTAL_JOB_LEASE_SECONDS` la durée après laquelle un verrou abandonné est
récupéré (1 à 3600 secondes). Les workers et l'API doivent partager la même base
PostgreSQL et la même configuration Proxmox.

Les profils sont gérés par un administrateur via
`/api/admin/image-profiles`. Leur désactivation bloque les nouveaux travaux et
ceux qui n'ont pas encore été soumis. Les profils ISO attachent encore une ISO
à la VM et ne créent aucun compte automatique. Seuls les profils cloud-init
clonés fournissent `guest_access`.

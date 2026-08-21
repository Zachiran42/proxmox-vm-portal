# Notifications internes

Le portail fournit un centre de notifications autonome, sans dépendance SMTP,
webhook ou service cloud. Chaque utilisateur ne peut consulter et modifier que
ses propres notifications.

## Événements couverts

- nouvelle demande à approuver, adressée aux administrateurs actifs ;
- approbation ou refus motivé, adressé au propriétaire de la demande ;
- provisionnement terminé avec succès ;
- échec confirmé du provisionnement ;
- résultat ambigu nécessitant une vérification administrative.
- entrée d'une VM dans la période de préavis avant échéance ;
- arrivée effective à échéance, avec rappel du blocage de démarrage.

Les notifications utilisent une clé de déduplication par destinataire. Une
reprise du worker ou une nouvelle lecture d'un résultat terminal ne génère donc
pas plusieurs alertes identiques. Elles ne contiennent aucun mot de passe, lien
Password Pusher, secret Proxmox, token ou donnée issue des journaux techniques.

Le worker balaie les échéances au plus une fois par minute. La clé de
déduplication contient l'échéance exacte : une prolongation ne répète pas
l'ancien rappel, mais autorise un nouveau rappel lorsque la nouvelle échéance
entre à son tour dans la période de préavis. Le balayage ne démarre, n'arrête et
ne supprime aucune VM.

## Utilisation

Le bouton de notification dans l'en-tête affiche le nombre d'éléments non lus.
L'utilisateur peut marquer un élément ou l'ensemble de la liste comme lu. Les
routes d'écriture exigent la session et le jeton CSRF :

```text
GET  /api/notifications?limit=50
POST /api/notifications/<id>/read
POST /api/notifications/read-all
```

Les alertes externes de supervision restent du ressort de Prometheus et
Alertmanager. Ce centre informe les utilisateurs du portail ; il ne remplace
pas l'astreinte ni le SIEM.

Après mise à jour, la migration attendue est
`0017_lifecycle_notifications (head)`.

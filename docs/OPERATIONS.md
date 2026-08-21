# Exploitation du parc

Le portail sépare désormais l'exploitation quotidienne de l'administration sensible.

## Rôles

- `operator` accède à la vue **Exploitation** en lecture seule : inventaire global, santé des services, file active, demandes en attente, incidents et échéances ;
- `admin` dispose de la même vue et des actions de remédiation : approbation, reprise de suivi, clôture d'incident et prolongation ;
- `user` ne voit que ses propres machines et n'accède pas à l'inventaire global.

Les paramètres, secrets d'intégration, utilisateurs, quotas et journaux d'audit restent dans la vue **Administration**, réservée aux administrateurs.

## Inventaire

`GET /api/operations/vms` accepte les filtres `search`, `status`, `node`, `owner`, `scope` et `limit`. `scope` vaut `active`, `archived` ou `all`; la limite maximale est 200.

La réponse expose uniquement les informations utiles à l'exploitation : propriétaire, placement, ressources, état, IP observée et échéance. Elle ne contient jamais le mot de passe invité, l'URL Password Pusher, le secret Proxmox ou le token NetBox.

L'inventaire reflète l'état connu du portail. Une IP issue du QEMU Guest Agent porte sa date d'observation; l'absence d'IP ne signifie donc pas nécessairement que la VM est hors ligne.

# Version 0.24.0

Cette version ajoute la gouvernance et l'exploitation quotidienne du parc sans
modifier le principe d'installation autonome sur Debian 13.

## Nouveautés

- circuit d'approbation administrateur optionnel avant tout appel Proxmox ou
  NetBox ;
- centre de notifications interne privé et dédupliqué ;
- notifications de résultat de provisionnement et de cycle de vie ;
- espace **Exploitation** avec inventaire global filtrable ;
- rôle `operator` en lecture seule, séparé de l'administration sensible ;
- rappels automatiques au propriétaire avant et après l'échéance d'une VM.

## Mise à jour

La mise à jour applique successivement les migrations :

```text
0015_vm_approval_workflow
0016_user_notifications
0017_lifecycle_notifications (head)
```

L'approbation reste désactivée par défaut afin de préserver le comportement des
installations existantes. Le worker ne supprime et n'arrête jamais une VM à son
échéance ; il bloque seulement les nouveaux démarrages selon la politique déjà
existante et crée les rappels internes.

Après installation, vérifier `/healthz`, la révision Alembic, la connexion aux
nœuds Proxmox et les vues **Exploitation** et **Administration**.

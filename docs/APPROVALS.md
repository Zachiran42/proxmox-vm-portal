# Approbation des demandes de VM

Le portail peut fonctionner en libre-service immédiat ou imposer une décision
administrative avant tout appel à Proxmox et NetBox. Le mode se règle dans
**Administration > Paramètres de provisionnement > Approbation administrative
obligatoire**. Il reste désactivé par défaut pour préserver l'installation
plug-and-play.

## Circuit de décision

Quand l'approbation est active :

1. la demande est validée et ses quotas sont réservés ;
2. son état devient `pending_approval` et le travail `approval_pending` ;
3. le worker ignore le travail : aucun clone, VMID ou enregistrement NetBox
   n'est créé ;
4. l'administrateur voit le propriétaire, le profil, le placement, les
   ressources et le réseau demandés ;
5. une approbation place le travail dans la file normale ;
6. un refus exige un motif visible par le demandeur, libère les quotas et
   efface immédiatement l'éventuel mot de passe invité chiffré.

Une décision ne peut être prise qu'une fois. Les demandes refusées peuvent être
archivées par leur propriétaire. L'échéance de la VM commence à l'approbation,
afin que le temps d'attente administratif ne réduise pas sa durée d'usage.

## Traçabilité et contrôle

Les événements `vm.approval.request`, `vm.approval.approve` et
`vm.approval.reject` sont inscrits dans le journal d'audit avec l'acteur et la
cible, sans secret. Les métriques agrégées exposent les états
`portal_jobs{status="approval_pending"}` et
`portal_vm_allocations{status="pending_approval"}` sans nom de VM ni identité.

Après une mise à jour, la migration attendue est :

```text
0015_vm_approval_workflow
```

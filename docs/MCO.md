# Cycle de vie et MCO des machines

Le portail attribue une échéance à chaque nouvelle VM. La politique se règle
dans **Administration > Paramètres de provisionnement** :

- durée de vie proposée par défaut à l'utilisateur ;
- durée maximale qu'un utilisateur peut demander ;
- nombre de jours de préavis avant affichage dans la supervision MCO.
- action automatique à l'expiration ;
- délai de grâce avant une éventuelle suppression.

Les VM créées avant l'installation de cette fonctionnalité restent marquées
`unmanaged` et ne reçoivent pas rétroactivement une date arbitraire.

## Comportement à l'échéance

Trois politiques sont disponibles :

- **Notifier uniquement** : comportement compatible avec les versions
  précédentes ; les actions **Démarrer** et **Redémarrer** sont bloquées ;
- **Arrêter et isoler** : le portail applique `DROP` en entrée/sortie, déconnecte
  `net0` puis programme l'arrêt via le worker ;
- **Isoler puis supprimer** : la même quarantaine est appliquée, puis la
  suppression est programmée uniquement après le délai de grâce configuré.

Après une mise à jour, **Notifier uniquement** reste sélectionné. Une activation
explicite par un administrateur est donc nécessaire avant toute suppression
automatique. Une prolongation annule la suppression planifiée, mais la
reconnexion réseau reste une action administrative distincte et auditée.

La page Administration affiche les VM expirées et celles qui entrent dans la
période de préavis. Un administrateur peut les prolonger de 30 ou 90 jours,
dans la limite maximale configurée. Chaque prolongation est inscrite dans le
journal d'audit avec l'ancienne échéance, la nouvelle échéance et le compte
administrateur responsable.

## Supervision

La métrique Prometheus `portal_vm_lifecycle` expose uniquement des totaux avec
les états `expired`, `warning` et `unmanaged`. Elle ne contient ni nom de VM,
ni utilisateur, ni adresse IP. En production, une alerte Alertmanager doit être
déclenchée sur les états `expired` et `warning`; la décision de prolonger ou de
supprimer reste humaine.

## Rapport consolidé

La page **Exploitation** consolide les VM jamais analysées, les mises à jour
APT disponibles, les redémarrages requis, les maintenances en échec, les
échéances, l'isolement réseau et les images obsolètes. Le rapport est calculé à
la demande à partir de l'état enregistré ; il ne lance aucune commande dans les
VM. Les administrateurs et opérateurs peuvent télécharger la liste d'actions au
format CSV avec **Télécharger le rapport MCO**.

L'interface affiche les douze premières priorités. Le CSV contient la liste
complète et doit être traité comme une donnée d'exploitation sensible.

Après mise à jour, vérifiez la migration puis l'interface :

```bash
cd /opt/proxmox-vm-portal
bash deploy/scripts/compose.sh exec -T api flask --app portal:create_app db current
curl --cacert /root/proxmox-vm-portal-local-ca.crt https://ADRESSE_DU_PORTAIL/healthz
```

La révision attendue est `0024_mco_siem`.

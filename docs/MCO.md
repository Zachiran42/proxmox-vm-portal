# Cycle de vie et MCO des machines

Le portail attribue une échéance à chaque nouvelle VM. La politique se règle
dans **Administration > Paramètres de provisionnement** :

- durée de vie proposée par défaut à l'utilisateur ;
- durée maximale qu'un utilisateur peut demander ;
- nombre de jours de préavis avant affichage dans la supervision MCO.

Les VM créées avant l'installation de cette fonctionnalité restent marquées
`unmanaged` et ne reçoivent pas rétroactivement une date arbitraire.

## Comportement à l'échéance

L'expiration n'entraîne aucune suppression automatique. Elle bloque seulement
les actions **Démarrer** et **Redémarrer**. L'utilisateur peut toujours arrêter
une machine encore active et demander sa suppression. Cette règle évite une
perte de données silencieuse tout en obligeant à régulariser les VM anciennes.

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

Après mise à jour, vérifiez la migration puis l'interface :

```bash
cd /opt/proxmox-vm-portal
bash deploy/scripts/compose.sh exec -T api flask --app portal:create_app db current
curl --cacert /root/proxmox-vm-portal-local-ca.crt https://ADRESSE_DU_PORTAIL/healthz
```

La révision attendue est `0017_lifecycle_notifications`.

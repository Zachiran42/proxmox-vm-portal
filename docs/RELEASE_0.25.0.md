# Version 0.25.0

Cette version consolide les fonctions de gouvernance et d'exploitation des VM
de test introduites après la version 0.24.0.

## Points principaux

- bac à sable réseau appliqué par défaut à toute nouvelle VM ;
- sortie temporaire sur demande GLPI, décision réservée aux administrateurs et
  retour automatique en sandbox à l'échéance ;
- catalogue de logiciels alimenté uniquement par les miroirs APT et registres
  OCI internes approuvés ;
- réinitialisation du mot de passe SSH demandée par l'administrateur puis choisie
  par le propriétaire de la VM ;
- analyse et application des mises à jour APT depuis l'administration ;
- cycle de vie des VM et des images, quarantaine et suppression planifiée ;
- suivi de l'usage de test, rapport MCO, supervision Zabbix et export SIEM ;
- migrations Alembic `0018` à `0025` appliquées automatiquement pendant la mise
  à jour hors ligne.

## Mise à jour

La méthode recommandée est le bundle hors ligne signé. L'installateur crée une
sauvegarde chiffrée avant l'arrêt des conteneurs, migre la base puis vérifie leur
santé. Le répertoire de repli temporaire est supprimé après réussite ; conservez
la sauvegarde chiffrée et sa clé `age` hors de la VM pour une restauration
durable.

Consultez [`DEPLOYMENT.md`](DEPLOYMENT.md) et [`AIRGAP.md`](AIRGAP.md) pour les
commandes complètes de vérification et d'installation.

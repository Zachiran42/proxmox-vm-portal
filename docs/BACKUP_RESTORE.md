# Sauvegarde, restauration et mise à jour

## Sauvegarde chiffrée

`deploy/scripts/backup.sh` crée un dump PostgreSQL au format custom, ajoute la
base Keycloak et le volume Password Pusher lorsqu'ils existent, puis chiffre
l'archive avec `age`. Aucun fichier clair n'est conservé après la commande.

```bash
sudo deploy/scripts/backup.sh
sudo age-keygen -y /chemin/hors-site/portal-backup.key
```

Conserver la clé privée `age` hors de la VM, avec une copie de secours contrôlée.
La sauvegarde inclut les secrets afin de préserver les clés de chiffrement ; elle
doit donc rester chiffrée à tout moment. Une sauvegarde uniquement présente sur
la VM source n'est pas une sauvegarde.

## Restauration

Sur une instance configurée et arrêtée pour maintenance :

```bash
sudo age-keygen -o /root/portal-restore.key  # exemple : utiliser la vraie clé
sudo AGE_IDENTITY_FILE=/root/portal-restore.key \
  deploy/scripts/restore.sh /sauvegardes/portal-AAAA.tar.gz.age --yes
```

Par défaut, les bases et le volume Password Pusher sont restaurés, mais la
configuration locale actuelle est conservée. Ajouter `--restore-config` pour
écraser `.env.production` et les fichiers secrets par ceux de l'archive. Cette
option est destinée à une reconstruction complète et nécessite ensuite une
revue des domaines, DNS et tokens externes.

Après chaque restauration : vérifier `compose.sh ps`, les journaux, la connexion,
les rôles, l'inventaire PVE et une création de VM de test. Révoquer les liens
Password Pusher qui n'auraient plus à être actifs.

## Mise à jour

```bash
cd /opt/proxmox-vm-portal
sudo deploy/scripts/update.sh
```

La procédure réalise d'abord une sauvegarde chiffrée, impose un `git pull
--ff-only`, reconstruit l'image, exécute les migrations puis attend la santé des
services. Les versions majeures de PostgreSQL, Keycloak et Password Pusher ne
doivent jamais être modifiées sans lire leurs notes de migration et réussir une
restauration en environnement de test. Le retour arrière applicatif consiste à
revenir à un tag Git compatible avec le schéma ; en cas de migration non
réversible, restaurer l'archive créée avant mise à jour.

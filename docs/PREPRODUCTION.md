# Qualification préproduction

Cette recette est volontairement séparée de l'installation : elle vérifie
l'état réel de la VM, du réseau et de Proxmox sans modifier l'infrastructure.
Elle doit être exécutée après chaque installation majeure et avant une version
publique.

## 1. VM Debian 13

Configurer d'abord le pare-feu nftables selon les réseaux d'administration et
clients. Conserver une session de secours pendant le changement de règles, puis
redémarrer complètement la VM. Depuis `/opt/proxmox-vm-portal` :

```bash
sudo deploy/scripts/qualify-preproduction.sh https://portal.example.com
```

Le script échoue si Debian 13/systemd, Docker au démarrage, les propriétaires et
modes des secrets, les services Compose, le confinement non-root/read-only,
nftables, TLS/HSTS/CSP ou l'inventaire Proxmox ne sont pas conformes. Il ne
modifie aucune règle de pare-feu et ne lit jamais la valeur d'un secret.

Après un résultat sans échec :

1. redémarrer la VM et relancer le script ;
2. confirmer que seuls 22 (réseaux d'administration), 80 et 443 sont exposés ;
3. vérifier le renouvellement ACME ou la chaîne de la CA interne ;
4. provoquer une sauvegarde, restaurer sur une VM isolée et comparer les
   utilisateurs, profils, quotas et événements d'audit ;
5. conserver la sortie horodatée dans le dossier de recette, hors du dépôt Git.

## 2. ACL du token Proxmox

Copier `deploy/proxmox/acl-policy.example.json` vers un fichier propre à
l'environnement, puis remplacer exactement les chemins du pool et des
stockages. Ne pas élargir `/pool/portal-vms` vers `/vms` ou `/` pour simplement
faire disparaître une erreur.

Sur un nœud Proxmox, depuis une copie en lecture seule du dépôt :

```bash
sudo deploy/scripts/audit-proxmox-token.sh \
  portal@pve provisioning /root/portal-acl-policy.json
```

Le script vérifie que l'utilisateur n'est pas `root@…`, que le token existe et
utilise la séparation de privilèges, exporte ses permissions effectives avec
`pveum user token permissions`, puis refuse tout chemin ou privilège absent de
la politique. Il ne demande et n'affiche pas le secret du token.

Les privilèges exacts dépendent de la méthode ISO ou clone cloud-init et de la
version Proxmox. Partir du minimum, exécuter la recette, puis ajouter seulement
le privilège explicitement refusé par Proxmox sur le chemin le plus étroit.
Tester aussi, avec un environnement jetable, qu'une création hors pool et une
allocation sur un stockage non autorisé reçoivent bien HTTP 403.

## 3. Identité et MFA

Suivre la section MFA de [`KEYCLOAK.md`](KEYCLOAK.md), puis valider au minimum :

- administrateur, opérateur et utilisateur avec le bon rôle applicatif ;
- utilisateur LDAP/LDAPS désactivé et utilisateur retiré d'un groupe ;
- second facteur obligatoire, inscription initiale, récupération et révocation ;
- URI de redirection exacte, PKCE S256 et refus d'une URI non déclarée ;
- compte local désactivé après validation du compte de secours.

## 4. Critère de passage

La préproduction est acceptée uniquement si le contrôle Debian ne contient
aucun échec, la politique ACL passe, les scénarios MFA et rôles sont signés par
un second relecteur, la restauration isolée réussit et aucun constat critique
ou élevé du pentest ne reste ouvert. Les preuves doivent mentionner le commit,
la version Debian, la version Proxmox, la version Keycloak et la date.

Références officielles :

- [Proxmox VE — permissions et tokens API](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf) ;
- [Keycloak — flux d'authentification, OTP et WebAuthn](https://www.keycloak.org/docs/latest/server_admin/) ;
- [Debian — pare-feu nftables](https://www.debian.org/doc/manuals/debian-handbook/sect.firewall-packet-filtering.en.html).

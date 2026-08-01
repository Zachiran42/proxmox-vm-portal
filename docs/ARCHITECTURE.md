# Architecture cible

## Périmètre et séparation des responsabilités

Le portail s'exécute sur une VM Debian dédiée. Il ne doit jamais exécuter de
commandes privilégiées sur l'hôte Proxmox. Il appelle exclusivement l'API HTTPS
de Proxmox avec un token de service non-root, limité par ACL à un pool, aux
stockages et aux opérations strictement nécessaires.

Le navigateur ne communique jamais directement avec Proxmox, Password Pusher ou
la base de données. L'API du portail applique l'authentification, l'autorisation,
les quotas et la validation avant de créer un travail asynchrone.

```text
Utilisateur -> reverse proxy TLS -> portail -> file de travaux -> worker
                                      |                         |
                                  PostgreSQL              API Proxmox
                                      |
                              fournisseur d'identité

Worker -> Password Pusher -> lien à usage limité retourné au portail
```

## Installation automatique

Attacher une ISO à une VM ne constitue pas une installation automatique. Chaque
système pris en charge doit avoir un profil d'installation approuvé et testé.

La voie recommandée est de construire des modèles Proxmox immuables avec Packer
à partir d'ISO dont la somme SHA-256 est épinglée, puis de cloner ces modèles avec
cloud-init. C'est plus rapide, plus reproductible et plus sûr qu'un installateur
interactif. Une seconde voie pourra générer des installations sans assistance
(preseed/autoinstall ou autounattend) pour les systèmes ne supportant pas
cloud-init.

L'interface doit donc distinguer :

- les ISO découvertes en lecture seule dans Proxmox ;
- les images publiées et installables, associées à un profil versionné ;
- les images désactivées ou non approuvées, impossibles à provisionner.

## Identité et autorisations

Keycloak est le fournisseur OIDC recommandé. Il peut fédérer LDAP ou LDAPS et
permet d'éviter de stocker les mots de passe d'entreprise dans le portail. Les
rôles applicatifs minimaux sont `admin`, `operator` et `user`.

Un mode local de secours peut exister pour une installation autonome, avec mots
de passe utilisant une fonction de dérivation mémoire-dure, MFA administrateur,
verrouillage progressif et sessions
révocables. Il ne doit pas être activé simultanément par défaut avec OIDC.

Chaque VM appartient à un utilisateur ou à un projet. Les quotas de CPU, RAM,
disque et nombre de VM sont contrôlés côté serveur. Toute opération sensible est
journalisée avec acteur, cible, résultat et identifiant de corrélation, sans
secret.

## Compte invité et remise du secret

Le compte créé dans la VM est nominatif et membre de `sudo`; la connexion SSH
directe de `root` et l'authentification SSH de `root` par mot de passe restent
désactivées. Une clé SSH est préférable. Si un mot de passe initial est demandé :

1. le worker génère un secret aléatoire à usage unique ;
2. seul son hash est injecté dans cloud-init ou le profil sans assistance ;
3. le secret clair est envoyé immédiatement à une instance Password Pusher
   explicitement configurée ;
4. le portail ne conserve que le lien de partage et ses métadonnées ;
5. le lien expire après un nombre de vues et une durée courts ;
6. l'utilisateur doit changer le mot de passe à la première connexion.

Le choix interne/externe de Password Pusher est une configuration
d'administrateur, jamais une URL libre fournie par un utilisateur.

## Contrôles de sécurité obligatoires

- TLS vérifié entre tous les composants, avec autorité interne configurable.
- Secrets injectés par fichiers Docker secrets ou gestionnaire de secrets, jamais
  dans Git, une image ou les journaux.
- Token Proxmox dédié, rotation documentée et ACL testées.
- Protection CSRF, cookies `Secure`/`HttpOnly`/`SameSite`, CSP et expiration de
  session.
- Limitation de débit distribuée sur connexion et provisionnement.
- Validation par listes d'autorisation des profils, pools, bridges et stockages.
- Travaux idempotents, suivi des UPID Proxmox et nettoyage après échec.
- Journal d'audit append-only et export possible vers un SIEM.
- Sauvegardes chiffrées de PostgreSQL et tests réguliers de restauration.
- Images de conteneurs non-root, versions épinglées, SBOM, analyse de dépendances
  et CI avec tests, lint, typage et analyse de secrets.

## Phases de livraison

1. Durcir l'API existante et exposer l'inventaire Proxmox en lecture seule.
2. Ajouter PostgreSQL, migrations, utilisateurs, rôles, quotas et audit. **Livré.**
3. Ajouter Keycloak/OIDC puis la fédération LDAP/LDAPS. **Intégration OIDC et
   guide de fédération livrés ; déploiement Keycloak à venir.**
4. Introduire la file de travaux, le suivi Proxmox et les profils d'images.
   **Livré pour les profils ISO et les clones de templates cloud-init ; les
   installations ISO sans assistance restent à ajouter.**
5. Ajouter la création du compte sudo et Password Pusher. **Livré pour les
   templates cloud-init prévalidés, avec remise réservée au propriétaire.**
6. Livrer Docker Compose, reverse proxy TLS, script d'installation Debian,
   sauvegardes et procédure de mise à jour. **Livré avec services optionnels
   Keycloak et Password Pusher, secrets par fichiers et restauration chiffrée.**
7. Réaliser une revue de menace et un test d'installation sur Debian vierge
   avant la première version publique. **Revue interne et banc Debian 13
   conteneurisé livrés ; validation sur VM systemd, ACL Proxmox et pentest
   indépendant encore requis avant publication.**

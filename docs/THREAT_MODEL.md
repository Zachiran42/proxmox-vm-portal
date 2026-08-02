# Modèle de menaces

État au 1er août 2026. Cette analyse s'appuie sur OWASP ASVS 5.0 comme catalogue
de contrôles ; elle ne constitue ni une certification ASVS ni un test
d'intrusion indépendant.

## Périmètre et actifs

Le périmètre comprend Caddy, l'API et le worker, PostgreSQL, les intégrations
OIDC/Keycloak, Proxmox et Password Pusher, ainsi que les scripts d'installation,
de mise à jour et de sauvegarde. Les actifs prioritaires sont le token Proxmox,
les identités et sessions, les secrets initiaux des invités, les autorisations
et quotas, le journal d'audit, les sauvegardes et la disponibilité du cluster.

Les frontières de confiance sont : navigateur/Caddy, Caddy/API, API/base,
worker/Proxmox, worker/Password Pusher, portail/fournisseur OIDC et
administrateur/hôte Debian. Proxmox, le fournisseur d'identité et Password
Pusher restent des systèmes externes qui doivent être durcis séparément.

## Acteurs et hypothèses

- utilisateur authentifié tentant d'élever ses privilèges ou de dépasser ses
  quotas ;
- attaquant anonyme visant l'authentification ou la disponibilité ;
- administrateur applicatif ou Debian compromis ;
- fournisseur, image ou dépendance compromis ;
- erreur d'exploitation lors d'une installation, mise à jour ou restauration.

L'hôte Debian est dédié, l'API n'est pas publiée directement et le token
Proxmox est non-root avec des ACL minimales. Un accès root à l'hôte, à Proxmox
ou au fournisseur d'identité reste hors de la barrière de sécurité applicative.

## Menaces et traitements

| Menace | Risque initial | Contrôles livrés | Risque résiduel |
|---|---:|---|---:|
| Vol ou rejeu de session | Élevé | TLS, cookies Secure/HttpOnly/SameSite, CSRF, rotation de session, CSP | Faible |
| Brute force et bourrage d'identifiants | Élevé | Limitation distribuée par compte+IP et par IP, clés HMAC, réponses 429, audit | Moyen derrière des proxys partagés |
| Élévation de rôle ou accès à la VM d'autrui | Critique | rôles côté serveur, contrôle de propriété, quotas transactionnels, audit | Moyen jusqu'au pentest |
| Injection de paramètres Proxmox | Critique | profils publiés, listes d'autorisation et validation stricte, aucun shell Proxmox | Faible |
| Compromission du token Proxmox | Critique | secret monté par fichier, refus de root, HTTPS, ACL minimales documentées | Élevé si ACL réelles trop larges |
| Fuite du mot de passe invité | Élevé | secret aléatoire non persisté, hash cloud-init, lien expirant réservé au propriétaire | Moyen selon Password Pusher |
| Altération ou effacement des audits | Élevé | table PostgreSQL append-only par trigger, API en lecture contrôlée | Moyen pour un administrateur DB |
| Archive de restauration malveillante | Élevé | chiffrement age, répertoire temporaire protégé, rejet des chemins absolus, traversées et liens | Faible |
| Mise à jour ou dépendance compromise | Critique | commit attendu explicite, base Docker par digest, verrou Python avec hashes, scans, SBOM, provenance, signature OIDC et déploiement refusant toute image sans digest/signature valides | Faible si le dépôt et l'identité approuvés restent protégés |
| Déni de service par provisionnement | Élevé | quotas, file asynchrone, limites de requête et de connexion | Moyen ; capacité PVE à superviser |
| Dépôt local modifiable lors de l'installation | Élevé | installateur root refusant tout fichier modifiable par groupe/autres | Faible |

## Risques à fermer avant une publication publique

1. Exécuter un test d'intrusion indépendant couvrant OIDC, CSRF, IDOR,
   contournement des quotas et concurrence.
2. Tester les ACL du token sur un cluster Proxmox de préproduction, notamment
   les refus hors pool, stockage, nœud et plage de VMID.
3. Valider l'installation sur une VM Debian 13 avec systemd, pare-feu, DNS/TLS,
   redémarrage complet et restauration réelle. Le banc conteneurisé ne couvre
   pas le noyau, systemd ni le pare-feu d'une VM.
4. Activer la MFA dans Keycloak et réserver le compte local à un compte de
   secours surveillé ; la MFA locale n'est pas encore implémentée.
5. Définir rétention, export SIEM, alertes et procédure de réponse aux incidents.
6. Activer la transparence publique Rekor lors du passage open source ; elle est
   volontairement désactivée tant que le dépôt et le package restent privés.

Ces points sont bloquants pour déclarer le portail prêt à une exposition
publique, mais pas pour poursuivre les essais privés en environnement isolé.

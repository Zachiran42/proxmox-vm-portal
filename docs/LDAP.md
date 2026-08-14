# Authentification LDAP et LDAPS native

Le portail peut authentifier directement les comptes d'un annuaire LDAP ou
Active Directory, sans imposer Keycloak. Deux transports sont acceptés :

- `ldaps://` avec validation stricte du certificat serveur ;
- `ldap://` uniquement avec négociation StartTLS obligatoire.

Le portail recherche le compte avec un utilisateur technique en lecture seule,
vérifie ensuite le mot de passe par un bind au nom de l'utilisateur et ne
conserve jamais ce mot de passe. Un compte applicatif est créé au premier accès,
puis son rôle est resynchronisé à chaque connexion d'après ses groupes LDAP.
Les groupes ont la priorité `admin`, `operator`, puis `user`. Un utilisateur qui
n'appartient plus à aucun groupe autorisé est refusé immédiatement.

## Configuration guidée

Sur la VM du portail :

```bash
cd /opt/proxmox-vm-portal
sudo bash deploy/scripts/configure-ldap.sh
```

Le script demande l'URL, la base de recherche, le compte de lecture, les groupes
et éventuellement le certificat de l'autorité interne. Il place le secret de
bind dans `deploy/secrets/portal_ldap_bind_password`, jamais dans
`.env.production`, valide réellement la connexion avant de redémarrer les
services et restaure l'ancienne configuration en cas d'échec.

Exemple Active Directory :

```dotenv
PORTAL_LDAP_URI=ldaps://dc01.chu.fr
PORTAL_LDAP_BIND_DN=CN=svc-portal,OU=Services,DC=chu,DC=fr
PORTAL_LDAP_BASE_DN=OU=Utilisateurs,DC=chu,DC=fr
PORTAL_LDAP_USER_FILTER=(sAMAccountName={username})
PORTAL_LDAP_USERNAME_ATTRIBUTE=sAMAccountName
PORTAL_LDAP_GROUP_ATTRIBUTE=memberOf
PORTAL_LDAP_GROUP_ADMIN=CN=Portal-Admins,OU=Groupes,DC=chu,DC=fr
PORTAL_LDAP_GROUP_OPERATOR=CN=Portal-Operators,OU=Groupes,DC=chu,DC=fr
PORTAL_LDAP_GROUP_USER=CN=Portal-Users,OU=Groupes,DC=chu,DC=fr
PORTAL_LDAP_CA_FILE=/run/secrets/portal_ldap_ca_cert
```

Le filtre doit contenir exactement une occurrence de `{username}`. Sa valeur est
échappée avant chaque recherche afin d'empêcher une injection LDAP. Les groupes
sont comparés comme des DN complets ; si l'annuaire utilise des groupes imbriqués,
adapter le filtre ou exposer l'appartenance effective dans l'attribut configuré.

## Mise en service sûre

1. créer un compte bind dédié, sans droit d'écriture et limité à la branche lue ;
2. utiliser un certificat émis par la PKI interne avec le nom DNS du serveur ;
3. affecter d'abord un compte de test au groupe `user` ;
4. exécuter `check-ldap`, puis tester connexion, changement de rôle, retrait de
   groupe et désactivation dans l'annuaire ;
5. conserver l'authentification locale pendant la recette ; ne la désactiver
   qu'après avoir validé un administrateur LDAP et la procédure de secours.

Contrôle manuel non interactif :

```bash
cd /opt/proxmox-vm-portal
bash deploy/scripts/compose.sh run --rm --no-deps api \
  flask --app portal:create_app check-ldap
```

LDAP/LDAPS natif fournit l'authentification et les rôles. Pour le SSO navigateur,
la MFA, WebAuthn ou des politiques d'identité centralisées, utiliser plutôt
Keycloak/OIDC et sa fédération LDAP décrite dans [`KEYCLOAK.md`](KEYCLOAK.md).

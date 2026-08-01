# Keycloak, OIDC et LDAP/LDAPS

## Client du portail

Le portail est un client OIDC confidentiel utilisant exclusivement Authorization
Code et PKCE S256. L'URI de retour doit être exacte, sans joker, et utiliser
HTTPS en production :

```text
https://portal.example/auth/oidc/callback
```

Le fichier [`deploy/keycloak/proxmox-portal-realm.json`](../deploy/keycloak/proxmox-portal-realm.json)
fournit un realm minimal importable. Avant l'import, Keycloak doit recevoir :

- `PORTAL_OIDC_CLIENT_SECRET`, secret aléatoire différent des autres secrets ;
- `PORTAL_OIDC_REDIRECT_URI`, URI exacte ci-dessus ;
- `PORTAL_PUBLIC_ORIGIN`, origine HTTPS sans chemin.

Les placeholders sont résolus par Keycloak pendant l'import. Le fichier ne doit
jamais être remplacé par un export contenant des secrets ou des utilisateurs.

Trois rôles sont créés : `portal-admin`, `portal-operator` et `portal-user`. Le
portail refuse toute identité qui ne possède aucun de ces rôles. Si plusieurs
rôles sont présents, le plus privilégié est retenu dans cet ordre : admin,
operator, user. Le rôle est resynchronisé à chaque connexion.

## Configuration du portail

```dotenv
PORTAL_LOCAL_AUTH_ENABLED=false
PORTAL_OIDC_ISSUER=https://id.example/realms/proxmox-portal
PORTAL_OIDC_CLIENT_ID=proxmox-vm-portal
PORTAL_OIDC_CLIENT_SECRET=CHANGE_ME_LOCAL_ONLY
PORTAL_OIDC_REDIRECT_URI=https://portal.example/auth/oidc/callback
PORTAL_OIDC_ROLE_ADMIN=portal-admin
PORTAL_OIDC_ROLE_OPERATOR=portal-operator
PORTAL_OIDC_ROLE_USER=portal-user
```

Le portail utilise le document `/.well-known/openid-configuration`, vérifie les
jetons avec Authlib, exige l'émetteur configuré et ne persiste ni access token,
ni refresh token, ni ID token. Le mode local peut rester actif pendant une
migration, puis doit être désactivé si Keycloak devient l'autorité unique.

## Fédération LDAP/LDAPS

La fédération est configurée dans Keycloak, jamais directement dans le portail.
Pour la production :

1. utiliser `ldaps://` avec vérification stricte du nom d'hôte ;
2. monter la CA interne dans `conf/truststores` ou définir
   `KC_TRUSTSTORE_PATHS` ;
3. utiliser un compte bind dédié en lecture seule et injecter son secret hors de
   Git ;
4. choisir `READ_ONLY` sauf besoin explicite et revu d'écriture LDAP ;
5. mapper des groupes LDAP dédiés vers les trois rôles du portail ;
6. tester connexion, synchronisation, désactivation et retrait de groupe avant
   d'activer le fournisseur en production.

Ne désactivez jamais la vérification TLS et n'utilisez pas un compte
d'administration de l'annuaire comme compte bind.

Références :

- <https://www.keycloak.org/securing-apps/oidc-layers>
- <https://www.keycloak.org/server/importExport>
- <https://www.keycloak.org/server/keycloak-truststore>
- <https://www.keycloak.org/docs/latest/server_admin/>

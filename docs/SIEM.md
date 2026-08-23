# Intégration SIEM / SOC

Le portail expose son journal d'audit sous forme NDJSON pour une collecte par
le SIEM. Le sens du flux est volontairement **SIEM vers portail** : le portail
n'ouvre aucune connexion sortante et un SIEM indisponible ne bloque jamais le
provisionnement.

## Configuration

Dans **Administration > Intégrations d'infrastructure > SIEM / SOC** :

1. générer un jeton ;
2. le copier immédiatement dans le coffre de secrets du collecteur ;
3. choisir tous les événements, les échecs et refus, ou les refus seuls ;
4. activer la collecte puis enregistrer.

Le jeton doit contenir au moins 32 caractères. Il est chiffré en base avec une
clé dérivée du secret de session, n'est jamais renvoyé par l'API et sa rotation
est auditée sans enregistrer sa valeur. Une authentification SIEM refusée est
également auditée avec une adresse source pseudonymisée.

## Collecte

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer $PORTAL_SIEM_TOKEN" \
  "https://portal.infra.chu.fr/api/siem/events?limit=500"
```

La réponse est `application/x-ndjson`. Chaque ligne contient un document proche
du modèle ECS avec `@timestamp`, `event`, `observer` et `portal`. Conserver les
deux en-têtes de réponse suivants pour la collecte incrémentale :

- `X-Portal-SIEM-Next-After` ;
- `X-Portal-SIEM-Next-After-ID`.

Les fournir ensuite dans `after` et `after_id`. Le couple évite de perdre des
événements partageant le même horodatage :

```text
/api/siem/events?limit=500&after=2026-08-22T10:00:00Z&after_id=UUID
```

La réponse porte `Cache-Control: no-store`. Restreindre le pare-feu du portail
aux adresses des collecteurs et placer le jeton dans leur coffre, jamais dans
une ligne de commande persistée ou un dépôt Git.

## Données exportées

L'export reprend les événements d'audit : action, résultat, identifiants
techniques, cible, identifiant de requête et détails contrôlés par
l'application. Il ne contient ni mot de passe, ni secret Proxmox/NetBox, ni
jeton SIEM. Les noms de VM, comptes et adresses éventuellement présents restent
des données d'exploitation sensibles auxquelles la politique de conservation
du SOC doit s'appliquer.

Après mise à jour, la migration attendue est `0024_mco_siem`.

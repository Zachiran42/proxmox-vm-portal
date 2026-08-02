# Observabilité et alertes

Le point `/metrics` est désactivé sans `PORTAL_METRICS_TOKEN`. En production,
le script d’installation génère ce secret dans
`deploy/secrets/portal_metrics_token` et Compose le monte en lecture seule. Le
scraper doit envoyer `Authorization: Bearer <jeton>` ; une session Web, un rôle
administrateur ou un paramètre d’URL ne remplacent jamais ce jeton.

Les métriques ne contiennent ni nom d’utilisateur, VMID, nom de VM, URL
Password Pusher, UPID ou autre identifiant individuel. Elles exposent seulement
des compteurs agrégés, l’âge du dernier heartbeat et la disponibilité Proxmox.

## Prometheus et Alertmanager

1. Copier `deploy/monitoring/prometheus-scrape.example.yml` dans la
   configuration Prometheus et remplacer la cible.
2. Monter le même jeton dans Prometheus avec le mode `0400`, hors du dépôt.
3. Copier `deploy/monitoring/prometheus-rules.yml` dans le répertoire de règles.
4. Configurer les receivers email ou webhook dans Alertmanager, avec TLS et ses
   secrets gérés par le mécanisme propre à Alertmanager.
5. Vérifier `promtool check config` et `promtool check rules` avant rechargement.

Le portail ne transmet directement aucune notification. Une panne du serveur
email, du webhook ou d’Alertmanager ne peut donc ni bloquer le worker ni influer
sur le provisionnement.

## Export du journal d’audit

Un administrateur peut télécharger jusqu’à 5 000 événements via
`GET /api/admin/audit-events.csv?limit=1000`. L’export utilise la session Web,
n’expose aucun mot de passe et neutralise les cellules pouvant être interprétées
comme des formules par un tableur. Traitez néanmoins ce fichier comme une donnée
sensible : stockage chiffré, accès restreint et durée de conservation définie.

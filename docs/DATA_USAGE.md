# Usage de test et données de santé

Le portail est destiné à fournir rapidement des machines de **test**. Il n'est
pas un hébergement de données de santé et ne doit recevoir aucune donnée patient
réelle, donnée nominative issue du SIH, copie de base de production ou secret de
production.

## Confirmation obligatoire

Avant chaque demande, l'utilisateur doit :

1. choisir une finalité parmi test technique, test fonctionnel, formation ou
   test de sécurité autorisé ;
2. confirmer explicitement qu'aucune donnée patient réelle, donnée de santé
   nominative ou donnée issue de production ne sera importée.

L'API applique la même règle que l'interface. Envoyer `false`, une chaîne de
caractères ou omettre la confirmation provoque un refus avant toute réservation
de quota, tout appel à NetBox et tout appel à Proxmox.

Le portail conserve uniquement :

- la finalité choisie ;
- la version de la politique (`no-real-patient-data-v1`) ;
- la date et l'heure de l'acceptation ;
- l'identifiant du compte déjà présent dans le journal d'audit.

Il ne demande ni ne conserve de description médicale, de nom de patient ou de
justification contenant des données sensibles.

## Machines antérieures à la migration

Les machines existantes reçoivent la finalité technique pour assurer la
compatibilité du schéma, mais leur politique reste
`legacy-unacknowledged` et leur date d'acceptation reste vide. Elles sont donc
distinguables des nouvelles demandes et ne reçoivent aucune preuve rétroactive
fictive.

## Limites et mesures complémentaires

La confirmation est un garde-fou organisationnel et une preuve d'information ;
elle ne détecte pas techniquement le contenu copié dans une VM. En contexte CHU,
elle doit être complétée par :

- des VLAN de test séparés et des flux minimaux ;
- l'interdiction d'accéder aux stockages et sauvegardes de production ;
- des jeux de données synthétiques ou correctement anonymisés selon une méthode
  validée par le DPO ;
- des règles de sensibilisation, de supervision et de traitement des incidents ;
- une procédure de suppression immédiate si une donnée réelle est découverte.

Une simple pseudonymisation ne doit pas être assimilée automatiquement à une
anonymisation. La qualification juridique et technique relève du DPO/RSSI et des
procédures de l'établissement.

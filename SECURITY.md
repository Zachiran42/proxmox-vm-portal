# Politique de sécurité

## Signaler une vulnérabilité

N'ouvrez pas d'issue publique contenant une vulnérabilité, un secret, une
preuve d'exploitation ou des données d'infrastructure. Utilisez le formulaire
privé **Security > Advisories > Report a vulnerability** du dépôt GitHub.

Indiquez si possible la version ou le commit affecté, l'impact, les étapes de
reproduction et une proposition de correction. Un accusé de réception sera
envoyé sous 72 heures. La correction et la publication seront coordonnées avec
le déclarant avant toute divulgation.

## Versions prises en charge

Le projet est encore en préversion privée. Seule la branche `main` à jour est
prise en charge. Aucune installation ne doit être exposée à Internet avant la
validation des prérequis et des risques résiduels décrits dans
[`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).

## Secrets compromis

En cas de fuite, révoquez immédiatement le token Proxmox et les secrets OIDC,
faites tourner les secrets de session et de base, invalidez les sessions puis
examinez le journal d'audit. Retirer un secret de Git ne suffit pas : il doit
être considéré comme compromis et remplacé.

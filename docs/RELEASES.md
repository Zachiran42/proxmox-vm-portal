# Releases sécurisées

Les releases sont produites uniquement par `.github/workflows/release.yml` lors
du push d'un tag SemVer `vMAJEUR.MINEUR.CORRECTIF`. Le workflow refuse un tag
dont la version ne correspond pas aux cinq surfaces contrôlées par
`deploy/scripts/verify-release.sh`.

## Artefacts publiés

Une release réussie fournit :

- l'image privée `ghcr.io/<propriétaire>/<dépôt>:<version>` et son digest ;
- une provenance BuildKit `mode=max` attachée à l'image ;
- un SBOM BuildKit SPDX attaché à l'image ;
- un SBOM SPDX JSON téléchargeable depuis la release ;
- `release-manifest.json`, qui lie version, commit, image, digest, SBOM et exécution ;
- la signature Sigstore du manifeste et `SHA256SUMS`.

L'image et le manifeste sont signés sans clé persistante : GitHub Actions émet
une identité OIDC de courte durée, acceptée par Sigstore. Les actions tierces
sont référencées par leur SHA complet et le workflow dispose seulement de
`contents: write`, `packages: write` et `id-token: write` dans le job de release.

## Confidentialité du dépôt privé

Le journal public Rekor est désactivé avec `--tlog-upload=false`. La signature
reste stockée dans le package GHCR privé et sa chaîne Fulcio est vérifiée dans
le workflow, mais elle ne bénéficie pas encore de la transparence publique de
Rekor. Lors du passage en open source, supprimer cette option et les options
`--insecure-ignore-tlog=true` correspondantes afin d'obtenir la preuve publique
et l'auditabilité maximales.

Les attestations GitHub natives ne sont pas utilisées comme contrôle principal :
elles nécessitent GitHub Enterprise Cloud pour un dépôt privé. Elles pourront
être ajoutées après publication publique sans remplacer les preuves OCI.

## Procédure de publication

1. Mettre à jour la version dans les surfaces contrôlées et fusionner sur
   `main` après succès du workflow `Security and quality`.
2. Exécuter localement `bash deploy/scripts/verify-release.sh vX.Y.Z`.
3. Créer un tag annoté localement : `git tag -a vX.Y.Z -m "Release vX.Y.Z"`.
4. Pousser uniquement ce tag : `git push origin vX.Y.Z`.
5. Vérifier le workflow `Secure release`, puis conserver le digest indiqué dans
   `release-manifest.json` pour tout déploiement approuvé.

Un tag ne doit jamais être déplacé ni réutilisé. Une correction produit une
nouvelle version. Dependabot surveille chaque semaine les actions GitHub,
l'image de base Docker et les dépendances Python ; ses PR restent soumises à la
CI et à une revue humaine.

## Vérification par un opérateur autorisé

Après authentification auprès de GHCR, installer Cosign et utiliser le digest du
manifeste, jamais le tag mutable :

```bash
cosign verify --insecure-ignore-tlog=true \
  --certificate-identity "https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/OWNER/REPO@sha256:DIGEST

sha256sum -c SHA256SUMS

cosign verify-blob --insecure-ignore-tlog=true \
  --bundle release-manifest.sigstore.json \
  --certificate-identity "https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release-manifest.json
```

Cette vérification confirme l'identité du workflow et l'intégrité des artefacts.
Elle ne remplace pas l'approbation du commit, la CI, la recette de préproduction
ni l'épinglage du digest lors du déploiement.

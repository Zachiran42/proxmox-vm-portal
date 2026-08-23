# Cycle de vie des images

Chaque profil publié possède une version immuable, par exemple `13.6-2026.08`.
Cette valeur est copiée dans la demande lors de sa création : une VM conserve
donc la trace exacte de l'image dont elle provient, même si le catalogue évolue.

## États administratifs

- **Active** : visible et utilisable pour une nouvelle VM ;
- **Dépréciée** : masquée aux nouvelles demandes, avec une date de fin de
  support et éventuellement une image de remplacement ;
- **Retirée** : masquée et considérée hors catalogue.

Le changement se fait dans **Administration > Images > Cycle de vie**. Il est
audité avec le nombre de VM existantes concernées. Une réactivation est
possible et republie explicitement l'image.

## Effet sur les VM existantes

Le portail ne remplace, ne redémarre et ne modifie jamais automatiquement une
VM lors du changement d'état d'une image. Il signale seulement :

- les VM créées avant le suivi des versions ;
- une image dépréciée, retirée ou arrivée en fin de support ;
- une version différente de la version actuellement enregistrée ;
- la disparition du profil d'origine.

L'avertissement et l'image de remplacement recommandée sont visibles par le
propriétaire dans le détail de sa VM et par les administrateurs dans
l'inventaire global. Une recréation depuis la nouvelle image reste une décision
explicite : les données et adaptations applicatives doivent être migrées selon
une procédure propre au test concerné.

## Convention de version

La version accepte lettres, chiffres, points, tirets, `_` et `+`, sur 64
caractères au maximum. Pour une exploitation CHU, une convention comme
`13.6-2026.08` permet de distinguer la version Debian du millésime de
durcissement. Ne modifiez pas la version d'un profil existant : publiez un
nouveau profil, qualifiez-le, puis dépréciez l'ancien en désignant le
remplacement.

Après mise à jour, la migration attendue est `0023_image_lifecycle`.

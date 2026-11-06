# Changelog

## 0.4.0 — 2026-11-06

### Coffres de clés : indépendance vis-à-vis du KMS

- **Sélecteur `KEYSTORE`** (`none`, `infisical`, `openbao`) et registre de coffres : chaque
  coffre est un paquet autonome qui s'enregistre et lit sa propre configuration. Ajouter un
  coffre (KMS de cloud…) ne touche ni la configuration générale, ni le moteur, ni l'API.
  `INFISICAL_ENABLED=true` reste accepté (équivaut à `KEYSTORE=infisical`).
- **OpenBao** (KV v2, compatible HashiCorp Vault) : authentification AppRole ou jeton, espace
  de noms, TLS 1.3 sans proxy ni redirection. Écriture en check-and-set 0 (jamais
  d'écrasement), puis `cas_required=true` et `delete_version_after=0s`. Une paire supprimée
  bloque le démarrage (restauration par `bao kv undelete`) au lieu d'en générer une nouvelle.
  La politique minimale du service (`create`, `read`) ne lui permet ni de remplacer ni de
  supprimer la paire. Le jeton AppRole est révoqué dès la paire chargée : sa valeur,
  passée par des chaînes Go non effaçables, ne vaut plus rien si elle fuit.
- **Effacement des secrets d'accès aux coffres** : chaque échange avec un coffre s'exécute sous
  `runtime/secret` (jeton dans l'en-tête HTTP, tampons `net/http` et `crypto/tls` effacés à leur
  libération, ramasse-miettes forcé après le démarrage), et les secrets lus dans l'environnement
  sont effacés dans la copie du runtime. Mesuré : plus aucune copie du jeton ni du `secret_id`
  dans la mémoire du processus (2 et 1 à 3 auparavant).
- **Correction** : `scrubEnviron`, qui efface les secrets du bloc d'environnement initial, en
  gardait une copie complète (tous les secrets passés par variable : `AUTH_TOKENS`, secrets
  des coffres) dans un tampon jamais effacé. Le tampon est maintenant effacé.
- **Format de bundle commun** à tous les coffres (`internal/keystore`), et commande
  **`pq-server -migrate-keys`** (`KEYSTORE_MIGRATE_FROM` vers `KEYSTORE`) : copie,
  relecture, comparaison ; rejouable, refuse d'écraser une autre paire, ne supprime jamais
  la source.
- **Avertissement `keystore_disabled`** en production sans coffre : la paire éphémère rend
  toute donnée chiffrée illisible au redémarrage.
- Le client HTTP durci (TLS 1.3, CA épinglée, réponses bornées, sans redirection) est
  partagé par les coffres ; la configuration Infisical quitte `internal/config` pour son paquet.

## 0.3.0 — 2026-11-05

Le chiffrement ne change pas : sans liaison d'identité, les enveloppes des versions
précédentes restent déchiffrables, octet pour octet.

### Sécurité : authentification, identité et isolation (voir SECURITY.md)

- **Jetons porteurs** (`AUTH_TOKENS` « nom:secret,… » ou `AUTH_TOKENS_FILE`) : exigés sur toute
  route sauf `/health` (réponse minimale) ; conservés par empreinte SHA-256, comparés en temps
  constant sur toutes les entrées ; secret ≥ 32 octets ; retirés de l'environnement.
- **Liaison d'identité** (`BIND_CLIENT_IDENTITY`) : l'identité du client (nom de jeton, de
  certificat ou UID du pair) entre dans le sel HKDF et l'AAD de chaque enveloppe. Un client ne
  peut rouvrir que ses propres enveloppes, quels que soient ses droits réseau. Exige une
  source d'identité ; sans identité, `401`.
- **Limites par identité** : rate-limit et plafond de concurrence comptés par client
  authentifié plutôt que par adresse.
- **Socket Unix** : `SOCKET_ALLOWED_UIDS` n'accepte que les pairs des UID listés
  (`SO_PEERCRED`, attesté par le noyau), fermés avant toute lecture sinon ; l'UID sert d'identité.
- **Journal d'audit** (`AUDIT_LOG`, actif par défaut) : une ligne par opération
  cryptographique (opération, client, source, `kid`, issue, corrélation), jamais de donnée.
- **Secrets d'environnement** : `AUTH_TOKENS` et `INFISICAL_CLIENT_SECRET` sont aussi
  effacés du bloc d'environnement initial du processus (`/proc/<pid>/environ`), que
  `os.Unsetenv` ne touche pas.
- **Déni de service** : `MAX_CONNECTIONS` borne les connexions simultanées par écouteur ;
  en-têtes limités à 64 Kio (au lieu de 1 Mio) ; `Content-Encoding` autre qu'`identity` refusé.
- **CI** (`.github/workflows/ci.yml`) : vet et tests (avec/sans `runtime/secret`, avec/sans
  `mock`, détecteur de concurrence), fuzzing, `govulncheck`, `gosec`, `gofmt`, construction de
  l'image et analyse Trivy.
- **SECURITY.md** : modèle de menace, table des attaques → contrôles → vérifications → résidus.

### Performance (×1,3 à ×2,7 selon l'opération, voir README §8c)

- Décodeur JSON strict en une seule passe (`secmem.DecodeStrict` réécrit, sans
  `json.Valid` ni `json.Unmarshal`), fuzzé en différentiel contre `encoding/json` : valeurs
  identiques quand les deux acceptent, jamais plus permissif.
- Chiffrement et déchiffrement AES-GCM en place dans le tampon de la requête
  (`SealInPlace`, `OpenInPlace`) ; réponses de plus de 16 Kio écrites en flux par blocs.
- Transcript assemblé et haché sur la pile ; HKDF-SHA256 et HMAC sur la pile, vérifiés contre
  `crypto/hkdf` et `crypto/hmac` (RFC 5869) ; contextes HKDF précalculés ; clé AES et sel dans
  des tableaux de pile ; résultat alloué hors du périmètre `runtime/secret` ; encapsulation
  ML-KEM dans des tampons fournis avec graine sur la pile.
- En-têtes de sécurité et `Content-Type` partagés (aucune allocation), un seul contexte de
  requête pour tous les middlewares, chemin rapide du plafond de concurrence sans minuterie,
  reconnaissance directe des types de contenu courants.
- Mesures (0.2.0 et 0.3.0 compilées à l'identique, médiane de 5 passes) : 1 Mio JSON 9,4 → 4,6 ms ;
  wrap-key 98 → 51 µs ; chiffrement ML-KEM-768 seul 84 → 32 µs (51 → 9 allocations) ; pic mémoire
  pour 16 requêtes de 10 Mio en parallèle 494 → 137 Mio.

### Ruptures de compatibilité

- `BIND_CLIENT_IDENTITY=true` change le contexte de chiffrement effectif : les enveloppes
  scellées sans liaison ne s'ouvrent plus avec (et inversement). À activer avant toute donnée.
- Un corps avec `Content-Encoding` autre qu'`identity` est refusé (`415`).
- En-têtes de requête limités à 64 Kio.
- API Go : `Sealer` et `Opener` gagnent `SealInPlace` et `OpenInPlace` ; `api.NewHandler`
  accepte des `HandlerOptions`.

## 0.2.0 — 2026-11-05

Le chiffrement ne change pas : les enveloppes produites par les versions précédentes restent
déchiffrables, octet pour octet.

### Corrections

- **Un chiffré de taille maximale était refusé au déchiffrement (`413`)** : `/decrypt` appliquait
  la même limite que `/encrypt`, alors que l'enveloppe ajoute la clé encapsulée, le nonce, le tag
  et l'expansion Base64. Les limites sont désormais posées par route : `/encrypt` accepte
  `MAX_PAYLOAD_BYTES`, `/decrypt` `1,5 × MAX_PAYLOAD_BYTES + 64 Kio`, ce qui garantit l'aller-retour
  en JSON et en binaire, même réencodé avec des `\/` (PHP). Testé à la limite pour chaque suite.
- Les clients d'exemple PHP et Node lisent aussi le champ `data` de `/decrypt`.

### Sécurité

- **Hygiène mémoire des secrets** (nouveau paquet `internal/secmem`) : corps de requête lu dans un
  tampon possédé qui efface ses anciennes copies en grandissant ; JSON décodé sans copie, champs
  Base64 et texte lus directement en octets effaçables (plus de chaînes Go immuables pour un clair
  ou une clé) ; corps brut effacé après décodage ; réponses construites dans un tampon effaçable,
  envoyées avec `Content-Length` puis effacées ; corps refusés lus dans un tampon local effacé.
  Mesuré : de 5–8 copies d'un clair ou d'une clé en mémoire après traitement à 0–2.
- **`runtime/secret`** : l'image est compilée avec `GOEXPERIMENT=runtimesecret` ; KEM, HKDF,
  AES-GCM et X25519 s'exécutent sous `secret.Do` (registres, pile et allocations internes effacés).
  Coût : ~+45 µs par opération. Un binaire compilé sans l'expérience le signale au démarrage.
- **JSON strict** : clés exactes (casse comprise), sans doublon ni échappement ; Base64 canonique ;
  `/encrypt` refuse `plaintext` et `data` ensemble ; les erreurs ne citent jamais une valeur.
- **Surface réduite** : seules `/encrypt` et `/decrypt` acceptent de gros corps ; les autres routes
  sont limitées à 64 Kio, et un `Content-Length` excessif est refusé avant lecture.
- **Réponse `/decrypt` bornée** : un clair UTF-8 coûteux à échapper (jusqu'à 6 octets JSON par
  octet) est renvoyé en `data` (Base64), ce qui borne la réponse et le budget mémoire.
- **Processus** : `RLIMIT_CORE=0` et `PR_SET_NO_NEW_PRIVS=1` s'ajoutent à `PR_SET_DUMPABLE=0`.
- **Infisical** : clé privée lue et écrite uniquement dans des tampons effaçables ; redirections
  HTTP refusées (une `307` renverrait la clé vers un autre hôte) ; noms de secrets validés
  (`[A-Za-z0-9_.-]`) avant d'entrer dans l'URL ; checksum comparé en temps constant.

### Ruptures de compatibilité

- **Infisical, format scindé supprimé** : la paire stockée en deux secrets
  (`INFISICAL_SECRET_PUBKEY_NAME` / `INFISICAL_SECRET_PRIVKEY_NAME`, antérieur au bundle atomique)
  n'est plus lue. Si ces secrets existent sans bundle `PQ_KEM_KEYPAIR`, le démarrage échoue
  (`keystore.ErrBootstrapForbidden`) au lieu de générer une paire neuve qui rendrait les données
  illisibles. Migration : créer le bundle (format documenté par `infisical.KeypairBundle`) à
  partir des deux secrets, puis les supprimer. `keystore.ErrPartialKeypair` disparaît.
- **JSON strict** : une clé dont la casse diffère (`"Data"`), dupliquée, inconnue, ou un Base64
  non canonique sont refusés (`400`) ; `encoding/json` les acceptait silencieusement.
- **`/decrypt`** : un clair UTF-8 dont l'encodage JSON dépasse sa taille Base64 de plus de 4 Kio
  est renvoyé en `data` ; les clients doivent lire les deux champs (c'était déjà le cas pour le binaire).
- **Routes de clés et KEM** : corps limité à 64 Kio (au lieu de `MAX_PAYLOAD_BYTES`).

### Maintenance

- Go 1.27.3 (`go.mod`, image `golang:1.27.3-alpine` épinglée par empreinte, `GOTOOLCHAIN=local`) ;
  `golang.org/x/sys` 0.49.0, `golang.org/x/crypto` 0.58.0 ; `govulncheck` épinglé (v1.9.0).
- `GOMEMLIMIT` est calculé automatiquement (85 % de la limite cgroup) quand il n'est pas fourni ;
  un avertissement signale une configuration dont le pire cas dépasse la mémoire.
- Pic mémoire mesuré pour 16 requêtes `/encrypt` de 10 Mio : 722 Mio → 494 Mio.
- Les tests d'intégration utilisent leurs propres types JSON (contrat vérifié en boîte noire).
- Suppression d'un exécutable Windows de 11,9 Mio (`-`) commité par erreur en 0.1.0 ;
  `.gitignore` l'exclut désormais.

## 0.1.2 — 2026-11-03

### Sécurité

- La lecture du corps d'une requête refusée (`429`, `503`), introduite en 0.1.1, est bornée à
  une seconde, puis la connexion est fermée : un client limité ne peut plus faire ingérer
  `MAX_PAYLOAD_BYTES` au serveur à chaque refus, ni retenir la connexion au goutte-à-goutte.
  La 0.1.1 n'a pas été publiée en image ; utiliser la 0.1.2.

## 0.1.1 — 2026-11-03

### Changements

- **Taille des requêtes** : `MAX_PAYLOAD_BYTES` vaut 10 Mio par défaut (au lieu de 1 Mio).
- **Budget mémoire** recalculé pour ces charges : `MAX_CONCURRENT_REQUESTS` passe à 16
  (une IP en occupe au plus 4), `MEM_LIMIT` du compose à `1G`, et `GOMEMLIMIT=900MiB`
  pour que le GC Go ramasse avant d'atteindre la limite du conteneur.

### Corrections

- Une requête refusée par le rate-limit (`429`) ou le plafond de concurrence (`503`) voit
  son corps lu et jeté (dans la limite `MAX_PAYLOAD_BYTES`) avant la réponse : le client
  reçoit le statut et le `Retry-After` au lieu d'une connexion coupée en plein envoi.

## 0.1.0 — 2026-11-02

Version qui traite la revue de sécurité et de qualité de la 0.0.1. Elle contient des
ruptures de compatibilité (pré-1.0). **Le chiffrement lui-même ne change pas** : sans
contexte de chiffrement, le transcript est identique octet pour octet, et les enveloppes
JSON produites par la 0.0.x restent déchiffrables.

### Ruptures de compatibilité

- **Transport** : en production, une écoute TCP hors loopback sans TLS refuse de démarrer,
  sauf `ALLOW_INSECURE_TCP=true`. `LISTEN_ADDRESS` vaut `127.0.0.1` par défaut (l'image
  Docker garde `0.0.0.0`).
- **Environnement** : seuls `development`, `dev`, `test`, `local` et `ci` lèvent les
  garde-fous de production ; toute autre valeur (`staging`, faute de frappe, vide) vaut production.
- **Mode simulé** : compilé uniquement avec `-tags mock` ; l'image publiée ne peut plus
  tourner en `MOCK_MODE`.
- **Infisical** : `INFISICAL_URL` doit être en `https://` en production.
- **Legacy** : `ALLOW_LEGACY_ENVELOPES` est supprimé ; les enveloppes binaires sans en-tête
  `PQ` et les enveloppes JSON sans `version`/`suite_id` sont refusées.
- **Format binaire** : émis en V3 (`kid` de 8 octets après `suite_id`) ; V2 reste lu.
- **`/decrypt`** : un seul champ renseigné — `plaintext` (UTF-8 valide) ou `data` (Base64).
- **Limites par défaut** : 1 Mio par requête, 500 req/s et rafale de 1000 par IP,
  32 requêtes simultanées (une IP en occupe au plus le quart).
- **`SOCKET_MODE`** : droits propriétaire/groupe uniquement (`0770` au plus).
- **API Go** : `Engine` est découpé en `Describer`, `Sealer`, `Opener` et `KeyAgreement` ;
  `Seal` et `GenerateDataKey` prennent un contexte de chiffrement ; `ExportKeys`,
  `KeyExporter`, `AllSuites`, `LookupSuiteByID` et `Suite.Scheme` disparaissent ; les clés
  se génèrent par `crypto.GenerateKeyPair`.

### Sécurité

- TLS 1.2+ et mTLS sur l'écouteur TCP (`TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CLIENT_CA_FILE`) ;
  en mTLS, certificat client exigé sur toutes les routes sauf `/health`.
- Identifiant de clé `kid` dans chaque enveloppe ; un `kid` étranger est refusé (`422`).
- Contexte de chiffrement client (`context`, en-tête `X-Encryption-Context`) lié au sel HKDF
  et à l'AAD : les enveloppes ne peuvent plus être échangées entre enregistrements ou locataires.
- Plafond de concurrence (`MAX_CONCURRENT_REQUESTS`, `503` + `Retry-After`,
  `pqc_overloaded_total`) ; rate-limit appliqué avant le plafond.
- Socket Unix créé directement avec ses permissions finales (umask), sans fenêtre avant le `chmod`.
- `X-Correlation-ID` client limité à `[A-Za-z0-9._:-]{1,128}`.
- Réponses d'Infisical lues avec une taille bornée.
- `key_length` négatif refusé (`400`) au lieu d'être remplacé par 32.
- Une panique après le début de la réponse coupe la connexion au lieu de corrompre le corps.

### Performance

- `VZEROUPPER` après chaque appel AVX2 de circl : sur les CPU Intel récents, l'état AVX
  « sale » pénalisait chaque bloc SHA-NI qui suivait. Chiffrement ~12× plus rapide
  (170 µs → 14 µs pour `HybridEncrypt/LocalKey`).
- La clé publique locale est mise en cache au lieu d'être recopiée à chaque `Seal`/`Open`.

### Corrections

- La sonde `-healthcheck` vise `LISTEN_ADDRESS` quand c'est une interface précise
  (elle visait toujours `127.0.0.1`).

### Maintenance

- `main()` découpé (`run`, `buildEngine`, `serve`, écouteurs, sonde, journalisation) ;
  tous les journaux passent par `slog`.
- Le client Infisical reçoit une structure `Options` dédiée au lieu de toute la configuration ;
  `internal/config` n'importe plus `internal/crypto`.
- Une seule règle d'environnement (`Config.IsProduction`).
- Erreur dédiée `ErrInvalidEnvelope` ; commentaires débarrassés des étiquettes « (DRY) »,
  « (SRP) »… ; `interface{}` remplacé par `any`.

## 0.0.1 — 2026-09-11

Première version publiée.

# Modèle de menace et contrôles

Ce document inventorie les familles d'attaques auxquelles un service de chiffrement exposé à
d'autres processus ou machines est confronté, et, pour chacune, le contrôle mis en œuvre
dans le code, la manière de le vérifier, et le résidu assumé. Il est la référence des
revues de sécurité : une attaque absente de cette table est une lacune à traiter.

## Frontière de confiance

Tout ce qui peut atteindre le gateway peut lui demander de déchiffrer. La sécurité repose
donc sur trois couches, cumulables :

1. **Transport** : socket Unix (permissions + `SOCKET_ALLOWED_UIDS`), ou TCP en TLS 1.3 avec
   mTLS (`TLS_CLIENT_CA_FILE` + `TLS_CLIENT_ALLOWED_NAMES`). Le TCP en clair est refusé en
   production hors loopback.
2. **Authentification applicative** : jetons porteurs (`AUTH_TOKENS`), comparés par
   empreinte en temps constant ; chaque client a une identité (nom de jeton, nom de
   certificat ou UID).
3. **Isolation cryptographique** (`BIND_CLIENT_IDENTITY`) : l'identité du client entre dans
   la dérivation de clé et l'AAD de chaque enveloppe. Un client qui obtiendrait l'accès au
   service ne peut rouvrir que ses propres enveloppes : la séparation entre locataires ne
   dépend plus seulement de l'administration réseau.

## Table des attaques

| Famille | Attaque | Contrôle | Vérification | Résidu |
| :--- | :--- | :--- | :--- | :--- |
| **Réseau** | Écoute passive (clairs, DEK en transit) | TLS 1.3 minimum, X25519MLKEM768 préféré ; TCP en clair refusé en production hors loopback (`ALLOW_INSECURE_TCP` explicite) | `TestMTLS_EndToEnd` (TLS 1.2 refusé) | Loopback et bridge Docker privé en clair si l'opérateur l'autorise |
| | Usurpation de client | mTLS + liste de noms ; jetons ; UID du pair attesté par le noyau | `TestMTLS_EndToEnd`, `TestTokenAuth`, `TestPeerCredListener_RejectsOtherUIDs` | Vol d'un jeton ou d'une clé client = compromission de ce client seul (avec la liaison d'identité) |
| | Forge d'identité réseau (`X-Forwarded-For`) | En-tête cru uniquement depuis `TRUSTED_PROXIES`, lu de droite à gauche | `TestClientIP_*` | Un proxy de confiance compromis peut tout forger |
| | Rebinding DNS, SSRF | Aucune requête sortante hors Infisical (URL de configuration, redirections refusées, CA épinglable) | `TestStoreKeys_RedirectsAreRefused`, `TestClient_RequiresTLS13AndPinnedCA` | — |
| **Déni de service** | Flot de connexions, Slowloris | `MAX_CONNECTIONS`, `ReadHeaderTimeout` 3 s, délais jamais nuls, en-têtes ≤ 64 Kio | `TestLimitListener_BoundsConcurrentConnections`, `TestConfig_SecurityValidations` | Épuisement de bande passante en amont |
| | Épuisement mémoire par gros corps | Limite par route (64 Kio hors `/encrypt`, `/decrypt`), `Content-Length` excessif refusé avant lecture, plafond de concurrence global et par source, `GOMEMLIMIT` dérivé du cgroup, swap interdit | `TestLimits_PerRoute`, `TestConcurrencyLimit_*`, mesure : 16 × 10 Mio → pic 494 Mio | — |
| | Rafales | Rate-limit par identité ou adresse (IPv6 par /64), corps des refus lu bon marché puis connexion fermée | `TestIdentityKeyedSourceLimit`, `TestDiscardBody_*` | Attaquant distribué : documenté |
| | Bombe de décompression, JSON profond | `Content-Encoding` refusé ; décodeur JSON plat (aucune imbrication), une passe, sans récursion | `TestContentEncodingRejected`, `FuzzDecodeStrict` | — |
| | Coût asymétrique (encapsulation vers clé fournie) | Validation de taille avant toute opération ; ML-KEM ~25 µs | benchmarks | — |
| **Analyse syntaxique** | Confusion d'analyseurs (clés dupliquées, casse, échappements), nombres ambigus | `secmem.DecodeStrict` : clés exactes, uniques, non échappées ; entiers sans fraction ni exposant ; Base64 canonique ; UTF-8 valide, sans demi-paire de substitution | `TestDecodeStrict_Rejects`, fuzz différentiel contre `encoding/json` | — |
| | Type de contenu trompeur (formulaire HTML, CSRF) | `Content-Type` exigé (`application/json` ou `application/octet-stream`), pas de CORS | `TestRequireContentTypeMiddleware` | — |
| | Enveloppe binaire malformée | Analyse bornée, longueurs vérifiées, fuzz | `FuzzParseBinaryEnvelope` | — |
| **Cryptographie** | Confusion d'usage, de suite, de version | Usage, suite et version liés au transcript (sel HKDF et AAD) ; `suite_id` et `version` obligatoires | `TestSecurity_*` | — |
| | Substitution de clé encapsulée ou de clé publique | Toutes deux dans le transcript ; `kid` vérifié | `TestSecurity_RecipientPKMutationRefused` | — |
| | Réutilisation de nonce | Une clé symétrique par message (HKDF du secret KEM frais) ; nonce `crypto/rand` | revue | — |
| | Échange d'enveloppes entre enregistrements ou locataires | Contexte de chiffrement client + liaison d'identité | `TestEncryptionContext_*`, `TestBindClientIdentity_IsolatesTenants` | — |
| | Clé publique hostile (ML-KEM hors modulus, X25519 d'ordre faible) | Contrôle FIPS 203 §7.2 de circl ; `ecdh` refuse un secret nul | `TestSecurity_*` | — |
| | Affaiblissement hybride | Combinateur HKDF des deux secrets, sel lié au chiffré composite | `TestSecurity_Dual*` | — |
| | Implémentation KDF/HMAC maison | HKDF sur pile vérifié contre `crypto/hkdf` et `crypto/hmac` (RFC 5869, 2 000 entrées aléatoires) | `TestHKDF_MatchesStandardLibrary` | — |
| **Canaux auxiliaires** | Temps de comparaison | Jetons : empreinte + comparaison constante sur toutes les entrées ; `kid` public | revue | — |
| | AES logiciel non constant | Avertissement `software_aes` sans AES-NI/ARMv8 | démarrage | L'opérateur doit choisir un hôte adapté |
| | Oracle d'erreur | `422` uniforme pour toute enveloppe invalide ; messages sans valeur | `TestDecodeStrict_ErrorsNeverQuoteValues` | Différence de temps décapsulation/AEAD, non exploitable sans secret |
| **Mémoire** | Secrets résiduels (dump, swap, tas) | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `PR_SET_NO_NEW_PRIVS`, swap interdit, tampons possédés et effacés, `runtime/secret`, chiffrement en place, réponses en flux, Base64 et JSON sans chaîne Go | `memscan` (0 copie après trafic), `TestOperationsRunUnderSecretErasure` | Tampons `bufio` de `net/http` jusqu'au trafic suivant ; structures internes des clés privées jusqu'à l'arrêt |
| | Secrets de démarrage | `INFISICAL_CLIENT_SECRET` et `AUTH_TOKENS` retirés de l'environnement dès lecture ; secret Infisical effacé après construction du moteur ; jetons conservés par empreinte seulement | `TestClient_CloseWipesSecret` | Copie initiale d'`environ` dans la pile de démarrage |
| **Chaîne d'approvisionnement** | Dépendance ou chaîne de compilation altérée | `go.sum`, `go mod verify`, `GOFLAGS=-mod=readonly`, `GOTOOLCHAIN=local`, image épinglée par empreinte, pas de `git` dans l'image, `govulncheck`, `gosec` et Trivy en CI | `.github/workflows/ci.yml` | — |
| **Conteneur** | Évasion, élévation | `scratch`, non-root, `cap_drop ALL`, `no-new-privileges`, racine en lecture seule, `tmpfs noexec`, limites CPU/mémoire/pids | compose | — |
| **Journaux** | Injection, fuite | Champs client tronqués à 256 octets, échappés par `slog` ; jamais de donnée ni de secret ; audit (opération, client, kid, issue) | `TestLoggerMiddleware_TruncatesClientFields` | — |
| **Clés** | Perte (paire éphémère) ou régénération accidentelle | Bundle Infisical vérifié, relu après écriture, état scindé historique bloquant | `TestFetchKeys_LegacyLayoutBlocksBootstrap` | Rotation et trousseau multi-`kid` : feuille de route |

## Hors périmètre

- La compromission de l'hôte (root, hyperviseur) donne accès à la mémoire du processus
  pendant une opération.
- Un client légitime peut toujours déchiffrer ce qu'il a lui-même le droit de déchiffrer :
  le service ne journalise que l'opération, pas le contenu.
- La longueur d'un chiffré révèle celle du clair (aucun bourrage).

## Signaler une vulnérabilité

Ouvrir un *security advisory* GitHub privé sur le dépôt, sans détail public avant correction.

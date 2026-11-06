package crypto

import "pq-crypto-service/internal/secmem"

// SecretErasure indique si les opérations cryptographiques s'exécutent sous runtime/secret.
// Compiler avec GOEXPERIMENT=runtimesecret pour l'activer (c'est le cas de l'image Docker).
const SecretErasure = secmem.Erasure

// withSecretErasure exécute f sous runtime/secret (voir secmem.Do) : registres et pile effacés
// au retour, allocations internes des bibliothèques (circl, AES-GCM, HKDF, X25519 : clés AES
// étendues, états Keccak, secrets intermédiaires) effacées dès leur libération.
func withSecretErasure(f func()) { secmem.Do(f) }

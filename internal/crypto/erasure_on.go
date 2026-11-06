//go:build goexperiment.runtimesecret

package crypto

import "runtime/secret"

// SecretErasure indique si les opérations cryptographiques s'exécutent sous runtime/secret.
const SecretErasure = true

// withSecretErasure exécute f sous runtime/secret.Do : à son retour, les registres et la pile
// utilisés par f (et tout ce qu'elle appelle : circl, AES-GCM, HKDF, X25519) sont effacés, et
// les allocations faites par f le sont dès que le ramasse-miettes les libère. Cela couvre les
// temporaires que Zeroize ne peut pas atteindre : clés AES étendues, états Keccak, secrets
// intermédiaires des bibliothèques. Effectif sur linux/amd64 et linux/arm64 ; ailleurs, f est
// simplement appelée.
func withSecretErasure(f func()) { secret.Do(f) }

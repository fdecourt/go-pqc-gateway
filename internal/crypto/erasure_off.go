//go:build !goexperiment.runtimesecret

package crypto

// SecretErasure indique si les opérations cryptographiques s'exécutent sous runtime/secret.
// Compiler avec GOEXPERIMENT=runtimesecret pour l'activer (c'est le cas de l'image Docker).
const SecretErasure = false

// withSecretErasure appelle f directement : sans GOEXPERIMENT=runtimesecret, seul l'effacement
// explicite (Zeroize) des tampons possédés par le service s'applique.
func withSecretErasure(f func()) { f() }

// Package credential définit les identifiants d'accès applicatifs partagés entre la
// configuration (qui les lit) et l'API (qui les vérifie), sans dépendance entre les deux.
package credential

import "crypto/sha256"

// Token est un jeton porteur admis : son nom (identité journalisée) et l'empreinte SHA-256
// de son secret. Le secret lui-même n'est jamais conservé par le service.
type Token struct {
	Name string
	Hash [sha256.Size]byte
}

// HashToken calcule l'empreinte d'un secret de jeton.
func HashToken(secret []byte) [sha256.Size]byte { return sha256.Sum256(secret) }

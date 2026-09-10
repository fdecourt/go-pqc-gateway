package crypto

import (
	"fmt"
)

const (
	// AES256KeySize définit la taille de clé symétrique en octets (256 bits).
	AES256KeySize = 32
	// GCMNonceSize définit la taille standard du Nonce GCM en octets (12 octets / 96 bits).
	GCMNonceSize = 12

	// ProtocolVersion identifie la version de la spécification cryptographique du service.
	ProtocolVersion = "GO-PQC-GATEWAY-V2"
)

// CryptoUsage spécifie l'usage cryptographique pour garantir la séparation stricte des domaines (anti-confusion).
type CryptoUsage string

const (
	// UsageDataEncryption désigne le chiffrement direct de charge utile applicative (/encrypt).
	UsageDataEncryption CryptoUsage = "DATA_ENCRYPTION"
	// UsageKeyWrapping désigne l'enveloppement de clé symétrique cliente (/wrap-key).
	UsageKeyWrapping CryptoUsage = "KEY_WRAPPING_DEK"
	// UsageKeyAgreement désigne l'accord de clé post-quantique pur (/kem/encapsulate).
	UsageKeyAgreement CryptoUsage = "KEY_AGREEMENT"
)

// BuildDomainContext construit la chaîne de contexte HKDF garantissant la séparation de domaine.
func BuildDomainContext(algo string, usage CryptoUsage) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s", ProtocolVersion, algo, usage))
}

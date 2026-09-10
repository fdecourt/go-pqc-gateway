package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// writePrefixedField écrit un préfixe de longueur uint32 (BigEndian) suivi des octets bruts (Encodage TLV).
func writePrefixedField(w io.Writer, b []byte) {
	var lenBuf [4]byte
	// #nosec G115
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	// #nosec G104
	_, _ = w.Write(lenBuf[:])
	if len(b) > 0 {
		// #nosec G104
		_, _ = w.Write(b)
	}
}

// writePrefixedString écrit un préfixe de longueur uint32 suivi d'une chaîne UTF-8.
func writePrefixedString(w io.Writer, s string) {
	writePrefixedField(w, []byte(s))
}

// HashCanonicalTranscript calcule l'empreinte SHA-256 d'un transcript canonique structuré TLV :
// version || len(label) || label || len(algo) || algo || len(usage) || usage || len(encap) || encap || len(pk) || pk
// Évite toute collision ou ambiguïté d'extension de longueur (RFC 9180 / NIST SP 800-108).
func HashCanonicalTranscript(label, algo string, usage CryptoUsage, encapKey, recipientPK []byte) []byte {
	h := sha256.New()
	writePrefixedString(h, ProtocolVersion)
	writePrefixedString(h, label)
	writePrefixedString(h, algo)
	writePrefixedString(h, string(usage))
	writePrefixedField(h, encapKey)
	writePrefixedField(h, recipientPK)
	return h.Sum(nil)
}

// BuildAAD calcule les données authentifiées supplémentaires (AAD) pour AES-GCM avec encodage canonique TLV.
func BuildAAD(algo string, usage CryptoUsage, encapKey, recipientPK []byte) []byte {
	return HashCanonicalTranscript("AAD", algo, usage, encapKey, recipientPK)
}

// BuildTranscriptSalt calcule le sel HKDF liant 100% de la transcription publique avec encodage canonique TLV.
func BuildTranscriptSalt(algo string, usage CryptoUsage, encapKey, recipientPK []byte) []byte {
	return HashCanonicalTranscript("SALT", algo, usage, encapKey, recipientPK)
}

// BuildCombinerSalt calcule le sel du combinateur hybride (X25519 + ML-KEM) avec encodage canonique TLV.
func BuildCombinerSalt(algoName string, dualEncapKey, recipientPK []byte) []byte {
	h := sha256.New()
	writePrefixedString(h, ProtocolVersion)
	writePrefixedString(h, "COMBINER-SALT")
	writePrefixedString(h, algoName)
	writePrefixedField(h, dualEncapKey)
	writePrefixedField(h, recipientPK)
	return h.Sum(nil)
}

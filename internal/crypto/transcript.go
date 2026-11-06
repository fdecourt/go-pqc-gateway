package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// transcriptScratch est la taille du tampon de pile dans lequel un transcript est assemblé
// avant d'être haché en un seul appel, sans allocation. Un transcript nominal fait au plus
// ~7,6 Kio (version, étiquette, algorithme, usage, clé encapsulée et clé publique ML-KEM-1024
// hybride de 1 600 octets chacune, contexte de 4 Kio, préfixes). Au-delà, le hachage est
// effectué en flux.
const transcriptScratch = 8192

// tlvField ajoute à dst un champ TLV : préfixe de longueur uint32 big-endian, puis octets.
func tlvField(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b))) // #nosec G115 -- longueurs bornées par les validations amont
	return append(dst, b...)
}

func tlvString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s))) // #nosec G115
	return append(dst, s...)
}

// tlvWrite écrit un champ TLV dans un hachage en flux.
func tlvWrite(h hash.Hash, b []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b))) // #nosec G115
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(b)
}

// transcriptLen majore la taille encodée de champs de longueurs données (4 octets de préfixe chacun).
func transcriptLen(lengths ...int) int {
	n := 0
	for _, l := range lengths {
		n += 4 + l
	}
	return n
}

// hashTranscriptInto calcule SHA-256 du transcript canonique TLV :
// version || len(label) || label || len(algo) || algo || len(usage) || usage || len(encap) || encap || len(pk) || pk
// étendu, si un contexte de chiffrement client est présent, de :
// ... || len("ENCRYPTION-CONTEXT") || "ENCRYPTION-CONTEXT" || len(ctx) || ctx
// Sans contexte, l'empreinte est identique à celle de la version 0.0.x : les enveloppes
// existantes restent déchiffrables. Chaque champ étant préfixé par sa longueur, deux
// encodages distincts ne peuvent pas coïncider (RFC 9180 / NIST SP 800-108).
//
// Le transcript est assemblé dans un tampon de pile et haché d'un seul appel : aucune
// allocation, et rien ne survit au retour. Un transcript trop long est haché en flux.
func hashTranscriptInto(out *[sha256.Size]byte, label, algo string, usage CryptoUsage, encapKey, recipientPK, encCtx []byte) {
	const ctxLabel = "ENCRYPTION-CONTEXT"
	need := transcriptLen(len(ProtocolVersion), len(label), len(algo), len(usage), len(encapKey), len(recipientPK))
	if len(encCtx) > 0 {
		need += transcriptLen(len(ctxLabel), len(encCtx))
	}
	if need <= transcriptScratch {
		var scratch [transcriptScratch]byte
		b := scratch[:0]
		b = tlvString(b, ProtocolVersion)
		b = tlvString(b, label)
		b = tlvString(b, algo)
		b = tlvString(b, string(usage))
		b = tlvField(b, encapKey)
		b = tlvField(b, recipientPK)
		if len(encCtx) > 0 {
			b = tlvString(b, ctxLabel)
			b = tlvField(b, encCtx)
		}
		*out = sha256.Sum256(b)
		Zeroize(scratch[:len(b)])
		return
	}
	h := sha256.New()
	tlvWrite(h, []byte(ProtocolVersion))
	tlvWrite(h, []byte(label))
	tlvWrite(h, []byte(algo))
	tlvWrite(h, []byte(usage))
	tlvWrite(h, encapKey)
	tlvWrite(h, recipientPK)
	if len(encCtx) > 0 {
		tlvWrite(h, []byte(ctxLabel))
		tlvWrite(h, encCtx)
	}
	h.Sum(out[:0])
}

// HashCanonicalTranscript calcule l'empreinte SHA-256 d'un transcript canonique sans contexte.
func HashCanonicalTranscript(label, algo string, usage CryptoUsage, encapKey, recipientPK []byte) []byte {
	var out [sha256.Size]byte
	hashTranscriptInto(&out, label, algo, usage, encapKey, recipientPK, nil)
	return out[:]
}

// BuildAAD calcule les données authentifiées (AAD) d'AES-GCM : transcript public et contexte client.
func BuildAAD(algo string, usage CryptoUsage, encapKey, recipientPK, encCtx []byte) []byte {
	var out [sha256.Size]byte
	hashTranscriptInto(&out, "AAD", algo, usage, encapKey, recipientPK, encCtx)
	return out[:]
}

// BuildTranscriptSalt calcule le sel HKDF : transcript public et contexte client.
func BuildTranscriptSalt(algo string, usage CryptoUsage, encapKey, recipientPK, encCtx []byte) []byte {
	var out [sha256.Size]byte
	hashTranscriptInto(&out, "SALT", algo, usage, encapKey, recipientPK, encCtx)
	return out[:]
}

// combinerSaltInto calcule le sel du combinateur hybride (X25519 + ML-KEM) :
// version || len("COMBINER-SALT") || "COMBINER-SALT" || len(algo) || algo || len(encap) || encap || len(pk) || pk
func combinerSaltInto(out *[sha256.Size]byte, algoName string, dualEncapKey, recipientPK []byte) {
	const label = "COMBINER-SALT"
	if transcriptLen(len(ProtocolVersion), len(label), len(algoName), len(dualEncapKey), len(recipientPK)) <= transcriptScratch {
		var scratch [transcriptScratch]byte
		b := scratch[:0]
		b = tlvString(b, ProtocolVersion)
		b = tlvString(b, label)
		b = tlvString(b, algoName)
		b = tlvField(b, dualEncapKey)
		b = tlvField(b, recipientPK)
		*out = sha256.Sum256(b)
		Zeroize(scratch[:len(b)])
		return
	}
	h := sha256.New()
	tlvWrite(h, []byte(ProtocolVersion))
	tlvWrite(h, []byte(label))
	tlvWrite(h, []byte(algoName))
	tlvWrite(h, dualEncapKey)
	tlvWrite(h, recipientPK)
	h.Sum(out[:0])
}

// BuildCombinerSalt calcule le sel du combinateur hybride (X25519 + ML-KEM) avec encodage canonique TLV.
func BuildCombinerSalt(algoName string, dualEncapKey, recipientPK []byte) []byte {
	var out [sha256.Size]byte
	combinerSaltInto(&out, algoName, dualEncapKey, recipientPK)
	return out[:]
}

package api

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"pq-crypto-service/internal/crypto"
)

// Format binaire (application/octet-stream), entiers en big-endian :
//
//	V3 (émis) : 'P' 'Q' 0x03 | suite_id(2) | kid(8) | len(encap)(2) | encap | nonce(12) | chiffré+tag
//	V2 (lu)   : 'P' 'Q' 0x02 | suite_id(2) |          len(encap)(2) | encap | nonce(12) | chiffré+tag
//
// V2, produit par la version 0.0.x, reste accepté en lecture : il ne porte pas de kid.
const (
	BinaryMagicByte1 = 'P'
	BinaryMagicByte2 = 'Q'
	BinaryFormatV2   = 0x02
	BinaryFormatV3   = 0x03

	binaryNonceSize = crypto.GCMNonceSize
	binaryMinCipher = 16 // tag GCM
)

// EncryptionContextHeader porte le contexte de chiffrement sur les routes binaires
// (équivalent du champ JSON "context"). Absent : aucun contexte.
const EncryptionContextHeader = "X-Encryption-Context"

func binaryEncryptionContext(r *http.Request) []byte {
	if v := r.Header.Get(EncryptionContextHeader); v != "" {
		return []byte(v)
	}
	return nil
}

// binaryEnvelope est la forme décodée d'une enveloppe binaire. Les tranches pointent dans le tampon source.
type binaryEnvelope struct {
	SuiteID  uint16
	KeyID    string // vide pour une enveloppe V2
	EncapKey []byte
	Nonce    []byte
	Cipher   []byte
}

func readBinaryBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	data, err := readRequestBody(r)
	if err != nil {
		respondBodyError(w, err)
		return nil, false
	}
	return data, true
}

func writeBinaryEnvelope(w http.ResponseWriter, p *crypto.SealedPayload) error {
	kid, err := hex.DecodeString(p.KeyID)
	if err != nil || len(kid) != crypto.KeyIDSize {
		return fmt.Errorf("kid de l'enveloppe invalide: %q", p.KeyID)
	}
	if len(p.EncapsulatedKey) > 0xFFFF {
		return fmt.Errorf("clé encapsulée trop longue: %d octets", len(p.EncapsulatedKey))
	}
	// En-tête assemblé dans un petit tampon ; le chiffré est écrit directement depuis son
	// tampon, sans copie.
	var hdr [3 + 2 + crypto.KeyIDSize + 2]byte
	hdr[0], hdr[1], hdr[2] = BinaryMagicByte1, BinaryMagicByte2, BinaryFormatV3
	binary.BigEndian.PutUint16(hdr[3:5], uint16(p.SuiteID))
	copy(hdr[5:5+crypto.KeyIDSize], kid)
	binary.BigEndian.PutUint16(hdr[5+crypto.KeyIDSize:], uint16(len(p.EncapsulatedKey))) // #nosec G115 -- borné ci-dessus

	setContentType(w, binaryMediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(hdr)+len(p.EncapsulatedKey)+len(p.Nonce)+len(p.Data)))
	w.WriteHeader(http.StatusOK)
	for _, part := range [][]byte{hdr[:], p.EncapsulatedKey, p.Nonce, p.Data} {
		if _, err := w.Write(part); err != nil {
			return nil // en-têtes envoyés : une erreur d'écriture n'a plus de destinataire
		}
	}
	return nil
}

func parseBinaryEnvelope(raw []byte) (binaryEnvelope, error) {
	var env binaryEnvelope
	if len(raw) < 3 || raw[0] != BinaryMagicByte1 || raw[1] != BinaryMagicByte2 {
		return env, errors.New("en-tête 'PQ' absent")
	}
	off := 3
	switch raw[2] {
	case BinaryFormatV2:
	case BinaryFormatV3:
		off += crypto.KeyIDSize // le kid suit le suite_id
	default:
		return env, fmt.Errorf("version binaire non supportée: %d", raw[2])
	}
	// suite_id(2) [+ kid] + len(encap)(2) + nonce + tag minimal
	if len(raw) < off+2+2+binaryNonceSize+binaryMinCipher {
		return env, errors.New("flux binaire trop court")
	}
	env.SuiteID = binary.BigEndian.Uint16(raw[3:5])
	if raw[2] == BinaryFormatV3 {
		env.KeyID = hex.EncodeToString(raw[5 : 5+crypto.KeyIDSize])
	}
	off += 2
	keyLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
	off += 2
	if len(raw) < off+keyLen+binaryNonceSize+binaryMinCipher {
		return env, errors.New("taille de clé encapsulée invalide")
	}
	env.EncapKey = raw[off : off+keyLen]
	env.Nonce = raw[off+keyLen : off+keyLen+binaryNonceSize]
	env.Cipher = raw[off+keyLen+binaryNonceSize:]
	return env, nil
}

// handleBinarySeal traite le scellement cryptographique direct pour le flux binaire application/octet-stream.
// Le fast-path binaire est optimisé exclusivement pour le débit local
// haute performance (IPC/socket Unix ou loopback KMS), chiffré vers la clé publique locale du service (recipientPK = nil).
// Pour chiffrer vers la clé publique d'un tiers arbitraire, utiliser la route JSON standard /encrypt avec recipient_public_key.
func (h *Handler) handleBinarySeal(w http.ResponseWriter, r *http.Request, usage crypto.CryptoUsage) {
	data, ok := readBinaryBody(w, r)
	if !ok {
		return
	}
	sealed, err := h.engine.SealInPlace(r.Context(), data, nil, usage, h.effectiveContext(r, binaryEncryptionContext(r)))
	h.auditOp(r, "seal:"+string(usage), kidOf(sealed), err)
	if err != nil {
		crypto.Zeroize(data)
		h.writeCryptoError(w, err)
		return
	}
	if !aliases(sealed.Data, data) {
		defer crypto.Zeroize(data) // chiffré ailleurs : le clair est encore dans data
	}
	if err := writeBinaryEnvelope(w, sealed); err != nil {
		h.writeCryptoError(w, err)
	}
}

func (h *Handler) handleBinaryOpen(w http.ResponseWriter, r *http.Request, usage crypto.CryptoUsage) {
	raw, ok := readBinaryBody(w, r)
	if !ok {
		return
	}
	defer crypto.Zeroize(raw) // le clair, déchiffré en place, y réside
	env, err := parseBinaryEnvelope(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "flux binaire invalide", err.Error())
		return
	}

	meta := EnvelopeMeta{SuiteID: env.SuiteID, Version: crypto.ProtocolVersion, KeyID: env.KeyID}
	plaintext, err := h.openEnvelope(r.Context(), meta, env.EncapKey, env.Nonce, env.Cipher, h.effectiveContext(r, binaryEncryptionContext(r)), usage)
	h.auditOp(r, "open:"+string(usage), env.KeyID, err)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	setContentType(w, binaryMediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(plaintext)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plaintext) // #nosec G104 -- en-têtes envoyés : une erreur d'écriture n'a plus de destinataire
}

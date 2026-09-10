package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"

	"pq-crypto-service/internal/crypto"
)

const (
	BinaryMagicByte1 = 'P'
	BinaryMagicByte2 = 'Q'
	BinaryFormatV2   = 0x02
)

func readBinaryBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			respondError(w, http.StatusRequestEntityTooLarge, "charge utile trop volumineuse", "la taille dépasse la limite autorisée")
			return nil, false
		}
		respondError(w, http.StatusBadRequest, "erreur lecture flux binaire", err.Error())
		return nil, false
	}
	return data, true
}

func writeBinaryEnvelope(w http.ResponseWriter, suiteID uint16, encapKey, nonce, cipher []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	// #nosec G104
	_, _ = w.Write([]byte{BinaryMagicByte1, BinaryMagicByte2, BinaryFormatV2})
	// #nosec G104
	_ = binary.Write(w, binary.BigEndian, suiteID)
	// #nosec G104,G115
	_ = binary.Write(w, binary.BigEndian, uint16(len(encapKey)))
	// #nosec G104
	_, _ = w.Write(encapKey)
	// #nosec G104
	_, _ = w.Write(nonce)
	// #nosec G104
	_, _ = w.Write(cipher)
}

func parseBinaryEnvelope(raw []byte, allowLegacy bool) (suiteID uint16, encapKey, nonce, cipher []byte, err error) {
	if len(raw) >= 3 && raw[0] == BinaryMagicByte1 && raw[1] == BinaryMagicByte2 {
		if raw[2] != BinaryFormatV2 {
			return 0, nil, nil, nil, fmt.Errorf("version binaire non supportée: %d", raw[2])
		}
		if len(raw) < 7+12+16 {
			return 0, nil, nil, nil, errors.New("flux binaire trop court")
		}
		suiteID = binary.BigEndian.Uint16(raw[3:5])
		keyLen := int(binary.BigEndian.Uint16(raw[5:7]))
		if len(raw) < 7+keyLen+12+16 {
			return 0, nil, nil, nil, errors.New("taille de clé encapsulée invalide")
		}
		return suiteID, raw[7 : 7+keyLen], raw[7+keyLen : 7+keyLen+12], raw[7+keyLen+12:], nil
	}

	if !allowLegacy {
		return 0, nil, nil, nil, crypto.ErrLegacyEnvelopesNotAllowed
	}
	if len(raw) < 2+12+16 {
		return 0, nil, nil, nil, errors.New("flux binaire trop court")
	}
	keyLen := int(binary.BigEndian.Uint16(raw[:2]))
	if len(raw) < 2+keyLen+12+16 {
		return 0, nil, nil, nil, errors.New("taille de clé encapsulée invalide")
	}
	return 0, raw[2 : 2+keyLen], raw[2+keyLen : 2+keyLen+12], raw[2+keyLen+12:], nil
}

// handleBinarySeal traite le scellement cryptographique direct pour le flux binaire application/octet-stream.
// NOTE D'ARCHITECTURE (D5) : Le fast-path binaire est optimisé exclusivement pour le débit local
// haute performance (IPC/socket Unix ou loopback KMS), chiffré vers la clé publique locale du service (recipientPK = nil).
// Pour chiffrer vers la clé publique d'un tiers arbitraire, utiliser la route JSON standard /encrypt avec recipient_public_key.
func (h *Handler) handleBinarySeal(w http.ResponseWriter, r *http.Request, usage crypto.CryptoUsage) {
	data, ok := readBinaryBody(w, r)
	if !ok {
		return
	}
	defer crypto.Zeroize(data)

	sealed, err := h.engine.Seal(r.Context(), data, nil, usage)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	writeBinaryEnvelope(w, uint16(sealed.SuiteID), sealed.EncapsulatedKey, sealed.Nonce, sealed.Data)
}

func (h *Handler) handleBinaryOpen(w http.ResponseWriter, r *http.Request, usage crypto.CryptoUsage) {
	raw, ok := readBinaryBody(w, r)
	if !ok {
		return
	}
	suiteID, encapKey, nonce, cipher, err := parseBinaryEnvelope(raw, h.allowLegacy)
	if err != nil {
		respondError(w, http.StatusBadRequest, "flux binaire invalide", err.Error())
		return
	}

	ver := ""
	if suiteID != 0 {
		ver = crypto.ProtocolVersion
	}
	plaintext, err := h.openEnvelope(r.Context(), EnvelopeMeta{SuiteID: suiteID, Version: ver}, encapKey, nonce, cipher, usage)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(plaintext)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	// #nosec G104
	_, _ = w.Write(plaintext)
}

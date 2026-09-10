package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pq-crypto-service/internal/crypto"
)

type Handler struct {
	engine      crypto.Engine
	allowLegacy bool
	startTime   time.Time
}

func NewHandler(engine crypto.Engine, allowLegacy bool) *Handler {
	return &Handler{
		engine:      engine,
		allowLegacy: allowLegacy,
		startTime:   time.Now(),
	}
}

func envelopeMeta(p *crypto.SealedPayload) EnvelopeMeta {
	return EnvelopeMeta{
		Algorithm: p.Algorithm,
		Version:   p.Version,
		SuiteID:   uint16(p.SuiteID),
	}
}

func b64Sealed(p *crypto.SealedPayload) (EnvelopeMeta, string, string, string) {
	return envelopeMeta(p),
		base64.StdEncoding.EncodeToString(p.EncapsulatedKey),
		base64.StdEncoding.EncodeToString(p.Nonce),
		base64.StdEncoding.EncodeToString(p.Data)
}

func isBinaryRequest(r *http.Request) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return mt == "application/octet-stream"
}

func (h *Handler) openEnvelope(ctx context.Context, meta EnvelopeMeta, encapKey, nonce, data []byte, usage crypto.CryptoUsage) ([]byte, error) {
	return h.engine.Open(ctx, &crypto.SealedPayload{
		Algorithm:       meta.Algorithm,
		Version:         meta.Version,
		SuiteID:         crypto.SuiteID(meta.SuiteID),
		EncapsulatedKey: encapKey,
		Nonce:           nonce,
		Data:            data,
	}, usage)
}

func acceptsBinary(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if mt == "application/octet-stream" {
			if qVal, ok := params["q"]; ok {
				if q, err := strconv.ParseFloat(qVal, 64); err == nil && q <= 0 {
					continue
				}
			}
			return true
		}
	}
	return false
}

func (h *Handler) writeCryptoError(w http.ResponseWriter, err error) {
	if errors.Is(err, crypto.ErrInvalidKey) ||
		errors.Is(err, crypto.ErrEmptyPayload) ||
		errors.Is(err, crypto.ErrInvalidPayloadSize) ||
		errors.Is(err, crypto.ErrUnsupportedAlgorithm) ||
		errors.Is(err, crypto.ErrMismatchedSuite) ||
		errors.Is(err, crypto.ErrMismatchedVersion) {
		respondError(w, http.StatusBadRequest, "paramètre invalide", "format d'enveloppe ou paramètres cryptographiques invalides")
		return
	}
	if errors.Is(err, crypto.ErrDecapsulationFailed) || errors.Is(err, crypto.ErrDecryptionFailed) {
		respondError(w, http.StatusUnprocessableEntity, "échec du déchiffrement", "données chiffrées altérées")
		return
	}
	log.Printf("[CRYPTO ERROR] Échec interne non divulgué: %v", err)
	respondError(w, http.StatusInternalServerError, "erreur cryptographique", "erreur cryptographique interne")
}

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		respondError(w, http.StatusMethodNotAllowed, "méthode non autorisée", "seuls GET et HEAD sont supportés")
		return
	}
	respondJSON(w, http.StatusOK, HealthResponse{
		Status:    "healthy",
		Service:   "pq-crypto-microservice",
		Algorithm: h.engine.Name(),
		MockMode:  h.engine.IsMock(),
		Timestamp: time.Now().UTC(),
		UptimeSec: int64(time.Since(h.startTime).Seconds()),
	})
}

func (h *Handler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	pkBytes := h.engine.GetPublicKey()
	if acceptsBinary(r) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pkBytes)
		return
	}
	respondJSON(w, http.StatusOK, PublicKeyResponse{
		Algorithm:    h.engine.Name(),
		PublicKey:    base64.StdEncoding.EncodeToString(pkBytes),
		KeySizeBytes: len(pkBytes),
	})
}

func (h *Handler) Encrypt(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if isBinaryRequest(r) {
		h.handleBinarySeal(w, r, crypto.UsageDataEncryption)
		return
	}
	var req EncryptRequest
	if !bindJSON(w, r, &req) {
		return
	}
	plaintext, err := req.GetBytes()
	if err != nil {
		respondError(w, http.StatusBadRequest, "charge utile invalide", err.Error())
		return
	}
	defer crypto.Zeroize(plaintext)
	recipientPK, err := req.GetRecipientPK()
	if err != nil {
		respondError(w, http.StatusBadRequest, "clé publique destinataire invalide", err.Error())
		return
	}
	sealed, err := h.engine.Seal(r.Context(), plaintext, recipientPK, crypto.UsageDataEncryption)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	meta, encap, nonce, ct := b64Sealed(sealed)
	respondJSON(w, http.StatusOK, EncryptResponse{
		EnvelopeMeta:    meta,
		EncapsulatedKey: encap,
		Nonce:           nonce,
		Ciphertext:      ct,
	})
}

func (h *Handler) Decrypt(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if isBinaryRequest(r) {
		h.handleBinaryOpen(w, r, crypto.UsageDataEncryption)
		return
	}
	var req DecryptRequest
	if !bindJSON(w, r, &req) {
		return
	}
	encapKey, nonce, ciphertext, err := req.Validate()
	if err != nil {
		respondError(w, http.StatusBadRequest, "paramètres invalides", err.Error())
		return
	}
	plaintext, err := h.openEnvelope(r.Context(), req.EnvelopeMeta, encapKey, nonce, ciphertext, crypto.UsageDataEncryption)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(plaintext)
	respondJSON(w, http.StatusOK, NewDecryptResponse(plaintext))
}

func (h *Handler) WrapKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if isBinaryRequest(r) {
		h.handleBinarySeal(w, r, crypto.UsageKeyWrapping)
		return
	}
	var req WrapKeyRequest
	if !bindJSON(w, r, &req) {
		return
	}
	keyBytes, err := req.GetKeyBytes()
	if err != nil {
		respondError(w, http.StatusBadRequest, "clé invalide", err.Error())
		return
	}
	defer crypto.Zeroize(keyBytes)
	recipientPK, err := req.GetRecipientPK()
	if err != nil {
		respondError(w, http.StatusBadRequest, "clé publique invalide", err.Error())
		return
	}
	sealed, err := h.engine.Seal(r.Context(), keyBytes, recipientPK, crypto.UsageKeyWrapping)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	meta, encap, nonce, wk := b64Sealed(sealed)
	respondJSON(w, http.StatusOK, WrapKeyResponse{
		EnvelopeMeta:    meta,
		EncapsulatedKey: encap,
		Nonce:           nonce,
		WrappedKey:      wk,
	})
}

func (h *Handler) UnwrapKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if isBinaryRequest(r) {
		h.handleBinaryOpen(w, r, crypto.UsageKeyWrapping)
		return
	}
	var req UnwrapKeyRequest
	if !bindJSON(w, r, &req) {
		return
	}
	encapKey, nonce, wrappedKey, err := req.Validate()
	if err != nil {
		respondError(w, http.StatusBadRequest, "paramètres invalides", err.Error())
		return
	}
	plaintextKey, err := h.openEnvelope(r.Context(), req.EnvelopeMeta, encapKey, nonce, wrappedKey, crypto.UsageKeyWrapping)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(plaintextKey)
	respondJSON(w, http.StatusOK, UnwrapKeyResponse{
		PlaintextKey: base64.StdEncoding.EncodeToString(plaintextKey),
		KeyLength:    len(plaintextKey),
	})
}

func (h *Handler) GenerateDataKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req GenerateDataKeyRequest
	if !bindOptionalJSON(w, r, &req) {
		return
	}
	recipientPK, err := req.GetRecipientPK()
	if err != nil {
		respondError(w, http.StatusBadRequest, "clé publique invalide", err.Error())
		return
	}
	keyLen := req.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}
	plaintextKey, wrapped, err := h.engine.GenerateDataKey(r.Context(), keyLen, recipientPK)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(plaintextKey)
	meta, encap, nonce, wk := b64Sealed(wrapped)
	respondJSON(w, http.StatusOK, GenerateDataKeyResponse{
		PlaintextKey:    base64.StdEncoding.EncodeToString(plaintextKey),
		EnvelopeMeta:    meta,
		EncapsulatedKey: encap,
		Nonce:           nonce,
		WrappedKey:      wk,
	})
}

func (h *Handler) KEMEncapsulate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req EncapsulateRequest
	if !bindOptionalJSON(w, r, &req) {
		return
	}
	recipientPK, err := req.GetRecipientPK()
	if err != nil {
		respondError(w, http.StatusBadRequest, "clé publique invalide", err.Error())
		return
	}
	res, err := h.engine.Encapsulate(r.Context(), recipientPK)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(res.SharedSecret)
	respondJSON(w, http.StatusOK, EncapsulateResponse{
		Algorithm:       res.Algorithm,
		EncapsulatedKey: base64.StdEncoding.EncodeToString(res.EncapsulatedKey),
		SharedSecret:    base64.StdEncoding.EncodeToString(res.SharedSecret),
	})
}

func (h *Handler) KEMDecapsulate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req DecapsulateRequest
	if !bindJSON(w, r, &req) {
		return
	}
	encapKey, err := req.GetKeyBytes()
	if err != nil {
		respondError(w, http.StatusBadRequest, "paramètre invalide", err.Error())
		return
	}
	sharedSecret, err := h.engine.Decapsulate(r.Context(), encapKey)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(sharedSecret)
	respondJSON(w, http.StatusOK, DecapsulateResponse{
		Algorithm:    h.engine.BaseName(),
		SharedSecret: base64.StdEncoding.EncodeToString(sharedSecret),
	})
}

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pq-crypto-service/internal/crypto"
)

type Handler struct {
	engine    crypto.Engine
	startTime time.Time
	// bindIdentity lie chaque enveloppe à l'identité du client (voir BoundContext).
	bindIdentity bool
	// audit journalise chaque opération cryptographique (client, kid, issue).
	audit bool
}

// HandlerOptions paramètre les gestionnaires.
type HandlerOptions struct {
	BindClientIdentity bool
	Audit              bool
}

func NewHandler(engine crypto.Engine, opts ...HandlerOptions) *Handler {
	h := &Handler{engine: engine, startTime: time.Now()}
	for _, o := range opts {
		h.bindIdentity, h.audit = o.BindClientIdentity, o.Audit
	}
	return h
}

// effectiveContext renvoie le contexte de chiffrement à lier : celui du client, préfixé de
// son identité si la liaison est active.
func (h *Handler) effectiveContext(r *http.Request, clientCtx []byte) []byte {
	if !h.bindIdentity {
		return clientCtx
	}
	return BoundContext(ClientIdentity(r), clientCtx)
}

// auditOp journalise une opération cryptographique. Le journal ne contient jamais de
// donnée : seulement l'opération, le client, le kid et l'issue.
func (h *Handler) auditOp(r *http.Request, op string, kid string, err error) {
	if !h.audit {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = "refused"
	}
	slog.Info("audit",
		slog.String("op", op),
		slog.String("client", ClientIdentity(r)),
		slog.String("source", r.RemoteAddr),
		slog.String("kid", kid),
		slog.String("outcome", outcome),
		slog.String("correlation_id", GetCorrelationID(r)),
	)
}

func isBinaryRequest(r *http.Request) bool { return mediaTypeOf(r) == binaryMediaType }

func kidOf(p *crypto.SealedPayload) string {
	if p == nil {
		return ""
	}
	return p.KeyID
}

// aliases indique si a et b partagent le même tableau sous-jacent (même premier octet).
func aliases(a, b []byte) bool { return len(a) > 0 && len(b) > 0 && &a[0] == &b[0] }

// requireJSON refuse (415) un corps qui n'est pas déclaré application/json sur une route sans
// variante binaire (RequireContentTypeMiddleware admet aussi l'octet-stream pour les routes qui l'ont).
func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength == 0 && r.Header.Get("Content-Type") == "" {
		return true
	}
	if mediaTypeOf(r) == jsonMediaType {
		return true
	}
	discardBody(w, r)
	respondError(w, http.StatusUnsupportedMediaType, "type de contenu non supporté", "Content-Type attendu : "+jsonMediaType)
	return false
}

func (h *Handler) openEnvelope(ctx context.Context, meta EnvelopeMeta, encapKey, nonce, data, encCtx []byte, usage crypto.CryptoUsage) ([]byte, error) {
	return h.engine.OpenInPlace(ctx, &crypto.SealedPayload{
		Algorithm:       meta.Algorithm,
		Version:         meta.Version,
		SuiteID:         crypto.SuiteID(meta.SuiteID),
		KeyID:           meta.KeyID,
		EncapsulatedKey: encapKey,
		Nonce:           nonce,
		Data:            data,
		Context:         encCtx,
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
		errors.Is(err, crypto.ErrInvalidEnvelope) ||
		errors.Is(err, crypto.ErrEmptyPayload) ||
		errors.Is(err, crypto.ErrInvalidPayloadSize) ||
		errors.Is(err, crypto.ErrUnsupportedAlgorithm) ||
		errors.Is(err, crypto.ErrMismatchedSuite) ||
		errors.Is(err, crypto.ErrMismatchedVersion) {
		respondError(w, http.StatusBadRequest, "paramètre invalide", "format d'enveloppe ou paramètres cryptographiques invalides")
		return
	}
	if errors.Is(err, crypto.ErrUnknownKey) {
		respondError(w, http.StatusUnprocessableEntity, "clé inconnue", "l'enveloppe a été chiffrée pour une autre clé (kid)")
		return
	}
	if errors.Is(err, crypto.ErrDecapsulationFailed) || errors.Is(err, crypto.ErrDecryptionFailed) {
		respondError(w, http.StatusUnprocessableEntity, "échec du déchiffrement", "données chiffrées altérées")
		return
	}
	slog.Error("crypto_internal_error", slog.String("error", err.Error()))
	respondError(w, http.StatusInternalServerError, "erreur cryptographique", "erreur cryptographique interne")
}

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		respondError(w, http.StatusMethodNotAllowed, "méthode non autorisée", "seuls GET et HEAD sont supportés")
		return
	}
	if clientUnauthenticated(r) {
		// Sonde sans certificat client : l'état suffit, sans décrire le service.
		respondJSON(w, http.StatusOK, MinimalHealthResponse{Status: "healthy"})
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
		w.Header().Set("Content-Type", binaryMediaType)
		w.Header().Set("Content-Length", strconv.Itoa(len(pkBytes)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pkBytes)
		return
	}
	respondJSON(w, http.StatusOK, PublicKeyResponse{
		Algorithm:    h.engine.Name(),
		PublicKey:    base64.StdEncoding.EncodeToString(pkBytes),
		KeyID:        h.engine.KeyID(),
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
	if !bindJSON(w, r, &req, false) {
		return
	}
	defer req.wipe()
	plaintext, err := req.payload()
	if err != nil {
		respondError(w, http.StatusBadRequest, "charge utile invalide", err.Error())
		return
	}
	// Chiffrement en place : le chiffré remplace le clair dans le tampon de la requête, que
	// le wipe différé efface après l'envoi.
	sealed, err := h.engine.SealInPlace(r.Context(), plaintext, req.RecipientPublicKey, crypto.UsageDataEncryption, h.effectiveContext(r, req.ContextBytes()))
	h.auditOp(r, "encrypt", kidOf(sealed), err)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	if aliases(sealed.Data, req.Data) {
		req.Data = nil // le tampon ne contient plus que le chiffré : rien à effacer
	}
	respondEnvelope(w, sealed, "ciphertext")
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
	if !bindJSON(w, r, &req, false) {
		return
	}
	h.openAndRespond(w, r, &req.envelopeFields, req.Ciphertext, crypto.UsageDataEncryption, respondPlaintext)
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
	if !bindJSON(w, r, &req, false) {
		return
	}
	defer req.wipe()
	if len(req.PlaintextKey) == 0 {
		respondError(w, http.StatusBadRequest, "clé invalide", "champ 'plaintext_key' manquant (clé Base64 requise)")
		return
	}
	sealed, err := h.engine.SealInPlace(r.Context(), req.PlaintextKey, req.RecipientPublicKey, crypto.UsageKeyWrapping, h.effectiveContext(r, req.ContextBytes()))
	h.auditOp(r, "wrap-key", kidOf(sealed), err)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	respondEnvelope(w, sealed, "wrapped_key")
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
	if !bindJSON(w, r, &req, false) {
		return
	}
	h.openAndRespond(w, r, &req.envelopeFields, req.WrappedKey, crypto.UsageKeyWrapping, respondUnwrappedKey)
}

// openAndRespond ouvre une enveloppe JSON décodée et transmet le clair à respond, puis l'efface.
func (h *Handler) openAndRespond(w http.ResponseWriter, r *http.Request, env *envelopeFields, data []byte,
	usage crypto.CryptoUsage, respond func(http.ResponseWriter, []byte)) {
	if err := env.complete(data); err != nil {
		respondError(w, http.StatusBadRequest, "paramètres invalides", err.Error())
		return
	}
	plaintext, err := h.openEnvelope(r.Context(), env.EnvelopeMeta, env.EncapsulatedKey, env.Nonce, data, h.effectiveContext(r, env.ContextBytes()), usage)
	h.auditOp(r, "open:"+string(usage), env.KeyID, err)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(plaintext)
	respond(w, plaintext)
}

func (h *Handler) GenerateDataKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !requireJSON(w, r) {
		return
	}
	var req GenerateDataKeyRequest
	if !bindJSON(w, r, &req, true) {
		return
	}
	plaintextKey, wrapped, err := h.engine.GenerateDataKey(r.Context(), req.KeyLength, req.RecipientPublicKey, h.effectiveContext(r, req.ContextBytes()))
	h.auditOp(r, "generate-key", kidOf(wrapped), err)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(plaintextKey)
	respondDataKey(w, plaintextKey, wrapped)
}

func (h *Handler) KEMEncapsulate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !requireJSON(w, r) {
		return
	}
	var req EncapsulateRequest
	if !bindJSON(w, r, &req, true) {
		return
	}
	res, err := h.engine.Encapsulate(r.Context(), req.RecipientPublicKey)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(res.SharedSecret)
	respondSharedSecret(w, res.Algorithm, res.EncapsulatedKey, res.SharedSecret)
}

func (h *Handler) KEMDecapsulate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !requireJSON(w, r) {
		return
	}
	var req DecapsulateRequest
	if !bindJSON(w, r, &req, false) {
		return
	}
	if len(req.EncapsulatedKey) == 0 {
		respondError(w, http.StatusBadRequest, "paramètre invalide", "champ 'encapsulated_key' manquant")
		return
	}
	sharedSecret, err := h.engine.Decapsulate(r.Context(), req.EncapsulatedKey)
	h.auditOp(r, "kem-decapsulate", h.engine.KeyID(), err)
	if err != nil {
		h.writeCryptoError(w, err)
		return
	}
	defer crypto.Zeroize(sharedSecret)
	respondSharedSecret(w, h.engine.BaseName(), nil, sharedSecret)
}

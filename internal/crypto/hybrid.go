package crypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// validateKeyLength garantit qu'une clé symétrique respecte les bornes autorisées (16 à 128 octets).
func validateKeyLength(n int) error {
	if n < 16 || n > 128 {
		return fmt.Errorf("%w: clé symétrique doit être comprise entre 16 et 128 octets", ErrInvalidPayloadSize)
	}
	return nil
}

// MaxEncryptionContextSize borne le contexte de chiffrement fourni par le client.
const MaxEncryptionContextSize = 4096

func validateEncryptionContext(encCtx []byte) error {
	if len(encCtx) > MaxEncryptionContextSize {
		return fmt.Errorf("%w: contexte de chiffrement de %d octets (max %d)", ErrInvalidPayloadSize, len(encCtx), MaxEncryptionContextSize)
	}
	return nil
}

// validateUsagePayload garantit qu'une règle unique et centralisée valide les charges selon leur usage cryptographique.
func validateUsagePayload(data []byte, usage CryptoUsage) error {
	switch usage {
	case UsageDataEncryption:
		if len(data) == 0 {
			return ErrEmptyPayload
		}
	case UsageKeyWrapping:
		return validateKeyLength(len(data))
	case UsageKeyAgreement:
		// Pas de charge utile pour l'accord de clé direct
	default:
		return fmt.Errorf("usage cryptographique non supporté: %s", usage)
	}
	return nil
}

// HybridEngine compose un KEM avec AES-256-GCM selon le schéma standard KEM+DEM.
type HybridEngine struct {
	kem      KEM
	name     string
	baseName string
	suiteID  SuiteID
	localPK  []byte // copie privée, lue sans recopie à chaque Seal/Open ; jamais exposée telle quelle
	keyID    string // identifiant de localPK, calculé une fois
	// Contextes HKDF (info) par usage, calculés une fois : aucune mise en forme sur le chemin chaud.
	infoData, infoWrap, infoAgree string
}

func newHybridEngine(kem KEM, suite Suite) *HybridEngine {
	pk := kem.PublicKey()
	return &HybridEngine{
		kem:       kem,
		name:      suite.Name,
		baseName:  suite.KEMName,
		suiteID:   suite.ID,
		localPK:   pk,
		keyID:     KeyID(pk),
		infoData:  string(BuildDomainContext(suite.Name, UsageDataEncryption)),
		infoWrap:  string(BuildDomainContext(suite.Name, UsageKeyWrapping)),
		infoAgree: string(BuildDomainContext(suite.KEMName, UsageKeyAgreement)),
	}
}

func (h *HybridEngine) SuiteID() SuiteID     { return h.suiteID }
func (h *HybridEngine) Name() string         { return h.name }
func (h *HybridEngine) BaseName() string     { return h.baseName }
func (h *HybridEngine) GetPublicKey() []byte { return append([]byte(nil), h.localPK...) }
func (h *HybridEngine) IsMock() bool         { return h.suiteID == SuiteMock }
func (h *HybridEngine) KeyID() string        { return h.keyID }

func (h *HybridEngine) algoForUsage(usage CryptoUsage) string {
	if usage == UsageKeyAgreement {
		return h.baseName
	}
	return h.name
}

func (h *HybridEngine) infoForUsage(usage CryptoUsage) string {
	switch usage {
	case UsageKeyAgreement:
		return h.infoAgree
	case UsageKeyWrapping:
		return h.infoWrap
	default:
		return h.infoData
	}
}

// deriveSecret centralise la séquence transcript + domaine + KDF selon un invariant cryptographique strict :
// clé = HKDF-SHA256(ikm = secret KEM, sel = SHA-256(transcript "SALT"), info = version:algo:usage).
func (h *HybridEngine) deriveSecret(key *[AES256KeySize]byte, rawSecret []byte, usage CryptoUsage, encapKey, recipientPK, encCtx []byte) error {
	if len(rawSecret) == 0 {
		return fmt.Errorf("secret partagé KEM invalide ou vide")
	}
	var salt [sha256.Size]byte
	hashTranscriptInto(&salt, "SALT", h.algoForUsage(usage), usage, encapKey, recipientPK, encCtx)
	defer Zeroize(salt[:])
	if err := hkdfSHA256Key(key, rawSecret, salt[:], h.infoForUsage(usage)); err != nil {
		return fmt.Errorf("erreur de dérivation de clé HKDF: %w", err)
	}
	return nil
}

// Seal réalise l'encapsulation KEM et le chiffrement AEAD avec liaison transcript et séparation d'usage.
// encCtx, facultatif, est lié au sel et à l'AAD : il devra être fourni à l'identique pour ouvrir.
// Le calcul s'exécute sous withSecretErasure : secret partagé, clé AES et leurs temporaires
// ne survivent pas à l'appel.
func (h *HybridEngine) Seal(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage, encCtx []byte) (*SealedPayload, error) {
	return h.sealOutside(ctx, plaintext, recipientPK, usage, encCtx, false)
}

// sealOutside alloue le résultat hors du périmètre runtime/secret (qui n'a pas à suivre des
// données publiques), puis fait le calcul sous effacement.
func (h *HybridEngine) sealOutside(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage, encCtx []byte, inPlace bool) (*SealedPayload, error) {
	p := &SealedPayload{Algorithm: h.name, Version: ProtocolVersion, SuiteID: h.suiteID, Nonce: make([]byte, GCMNonceSize)}
	var err error
	withSecretErasure(func() { err = h.seal(p, ctx, plaintext, recipientPK, usage, encCtx, inPlace) })
	if err != nil {
		return nil, err
	}
	return p, nil
}

// SealInPlace est Seal, mais consomme plaintext : si la capacité du tampon le permet
// (len + InPlaceSlack), le chiffré y remplace le clair, qui n'est alors copié nulle part.
func (h *HybridEngine) SealInPlace(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage, encCtx []byte) (*SealedPayload, error) {
	return h.sealOutside(ctx, plaintext, recipientPK, usage, encCtx, true)
}

// seal remplit p (alloué par l'appelant) ; s'exécute sous runtime/secret.
func (h *HybridEngine) seal(p *SealedPayload, ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage, encCtx []byte, inPlace bool) error {
	if err := validateUsagePayload(plaintext, usage); err != nil {
		return err
	}
	if err := validateEncryptionContext(encCtx); err != nil {
		return err
	}

	effectivePK, kid := h.localPK, h.keyID
	if len(recipientPK) > 0 {
		effectivePK, kid = recipientPK, KeyID(recipientPK)
	}

	encapKey, sharedSecret, err := h.kem.Encapsulate(ctx, recipientPK)
	if err != nil {
		return err
	}
	defer Zeroize(sharedSecret)

	var symKey [AES256KeySize]byte
	defer Zeroize(symKey[:])
	if err := h.deriveSecret(&symKey, sharedSecret, usage, encapKey, effectivePK, encCtx); err != nil {
		return fmt.Errorf("dérivation symétrique: %w", err)
	}

	var aad [sha256.Size]byte
	hashTranscriptInto(&aad, "AAD", h.name, usage, encapKey, effectivePK, encCtx)
	ciphertext, err := sealSymmetric(symKey[:], p.Nonce, plaintext, aad[:], inPlace)
	if err != nil {
		return fmt.Errorf("chiffrement symétrique: %w", err)
	}
	p.KeyID, p.EncapsulatedKey, p.Data = kid, encapKey, ciphertext
	return nil
}

// Open réalise la décapsulation KEM et le déchiffrement AEAD avec vérification stricte du domaine d'usage.
// Le clair renvoyé appartient à l'appelant, qui doit l'effacer (Zeroize) après usage.
func (h *HybridEngine) Open(ctx context.Context, payload *SealedPayload, usage CryptoUsage) (plaintext []byte, err error) {
	withSecretErasure(func() { plaintext, err = h.open(ctx, payload, usage, false) })
	return plaintext, err
}

// OpenInPlace est Open, mais consomme payload.Data : le clair y remplace le chiffré.
func (h *HybridEngine) OpenInPlace(ctx context.Context, payload *SealedPayload, usage CryptoUsage) (plaintext []byte, err error) {
	withSecretErasure(func() { plaintext, err = h.open(ctx, payload, usage, true) })
	return plaintext, err
}

func (h *HybridEngine) open(ctx context.Context, payload *SealedPayload, usage CryptoUsage, inPlace bool) ([]byte, error) {
	if payload == nil || len(payload.EncapsulatedKey) == 0 || len(payload.Nonce) == 0 || len(payload.Data) == 0 {
		return nil, fmt.Errorf("%w: charge utile scellée incomplète ou corrompue", ErrInvalidEnvelope)
	}

	if err := ValidateEnvelopeMeta(EnvelopeMetadata{
		Version:   payload.Version,
		SuiteID:   payload.SuiteID,
		Algorithm: payload.Algorithm,
	}, h.suiteID, h.name); err != nil {
		return nil, err
	}
	if err := validateEncryptionContext(payload.Context); err != nil {
		return nil, err
	}
	// Le kid est facultatif (enveloppes 0.0.x) ; s'il est présent, il doit désigner la clé locale.
	if payload.KeyID != "" && payload.KeyID != h.keyID {
		return nil, fmt.Errorf("%w: kid '%s' (clé locale '%s')", ErrUnknownKey, payload.KeyID, h.keyID)
	}

	sharedSecret, err := h.kem.Decapsulate(ctx, payload.EncapsulatedKey)
	if err != nil {
		return nil, err
	}
	defer Zeroize(sharedSecret)

	effectivePK := h.localPK
	var symKey [AES256KeySize]byte
	defer Zeroize(symKey[:])
	if err := h.deriveSecret(&symKey, sharedSecret, usage, payload.EncapsulatedKey, effectivePK, payload.Context); err != nil {
		return nil, fmt.Errorf("dérivation symétrique: %w", err)
	}

	var aad [sha256.Size]byte
	hashTranscriptInto(&aad, "AAD", h.name, usage, payload.EncapsulatedKey, effectivePK, payload.Context)
	plaintext, err := openSymmetric(symKey[:], payload.Nonce, payload.Data, aad[:], inPlace)
	if err != nil {
		return nil, err
	}

	if err := validateUsagePayload(plaintext, usage); err != nil {
		Zeroize(plaintext)
		return nil, err
	}

	return plaintext, nil
}

// GenerateDataKey génère une clé de données aléatoire et la renvoie en clair et enveloppée.
// La clé en clair appartient à l'appelant, qui doit l'effacer (Zeroize) après usage.
func (h *HybridEngine) GenerateDataKey(ctx context.Context, keyLength int, recipientPK, encCtx []byte) (key []byte, wrapped *SealedPayload, err error) {
	withSecretErasure(func() { key, wrapped, err = h.generateDataKey(ctx, keyLength, recipientPK, encCtx) })
	return key, wrapped, err
}

func (h *HybridEngine) generateDataKey(ctx context.Context, keyLength int, recipientPK, encCtx []byte) ([]byte, *SealedPayload, error) {
	if keyLength == 0 {
		keyLength = AES256KeySize
	}
	if err := validateKeyLength(keyLength); err != nil {
		return nil, nil, err
	}
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("génération entropie clé: %w", err)
	}
	wrapped := &SealedPayload{Algorithm: h.name, Version: ProtocolVersion, SuiteID: h.suiteID, Nonce: make([]byte, GCMNonceSize)}
	if err := h.seal(wrapped, ctx, key, recipientPK, UsageKeyWrapping, encCtx, false); err != nil {
		Zeroize(key)
		return nil, nil, err
	}
	return key, wrapped, nil
}

// Encapsulate réalise un accord de clé KEM direct ; le secret dérivé renvoyé appartient à
// l'appelant, qui doit l'effacer après usage.
func (h *HybridEngine) Encapsulate(ctx context.Context, recipientPK []byte) (res *KeyAgreementResult, err error) {
	withSecretErasure(func() { res, err = h.encapsulate(ctx, recipientPK) })
	return res, err
}

func (h *HybridEngine) encapsulate(ctx context.Context, recipientPK []byte) (*KeyAgreementResult, error) {
	effectivePK := recipientPK
	if len(effectivePK) == 0 {
		effectivePK = h.localPK
	}

	encapKey, rawSecret, err := h.kem.Encapsulate(ctx, recipientPK)
	if err != nil {
		return nil, err
	}
	defer Zeroize(rawSecret)

	derived := make([]byte, AES256KeySize)
	if err := h.deriveSecret((*[AES256KeySize]byte)(derived), rawSecret, UsageKeyAgreement, encapKey, effectivePK, nil); err != nil {
		Zeroize(derived)
		return nil, fmt.Errorf("dérivation secret d'accord de clé: %w", err)
	}

	return &KeyAgreementResult{
		Algorithm:       h.baseName,
		EncapsulatedKey: encapKey,
		SharedSecret:    derived,
	}, nil
}

// Decapsulate retrouve le secret d'un accord de clé KEM ; le secret renvoyé appartient à
// l'appelant, qui doit l'effacer après usage.
func (h *HybridEngine) Decapsulate(ctx context.Context, encapsulatedKey []byte) (secret []byte, err error) {
	withSecretErasure(func() { secret, err = h.decapsulate(ctx, encapsulatedKey) })
	return secret, err
}

func (h *HybridEngine) decapsulate(ctx context.Context, encapsulatedKey []byte) ([]byte, error) {
	if len(encapsulatedKey) == 0 {
		return nil, fmt.Errorf("%w: clé encapsulée vide", ErrInvalidKey)
	}

	rawSecret, err := h.kem.Decapsulate(ctx, encapsulatedKey)
	if err != nil {
		return nil, err
	}
	defer Zeroize(rawSecret)

	effectivePK := h.localPK
	derived := make([]byte, AES256KeySize)
	if err := h.deriveSecret((*[AES256KeySize]byte)(derived), rawSecret, UsageKeyAgreement, encapsulatedKey, effectivePK, nil); err != nil {
		Zeroize(derived)
		return nil, err
	}
	return derived, nil
}

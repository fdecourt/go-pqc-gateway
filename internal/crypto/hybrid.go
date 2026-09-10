package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
)

// validateKeyLength garantit qu'une clé symétrique respecte les bornes autorisées (16 à 128 octets).
func validateKeyLength(n int) error {
	if n < 16 || n > 128 {
		return fmt.Errorf("%w: clé symétrique doit être comprise entre 16 et 128 octets", ErrInvalidPayloadSize)
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
	kem         KEM
	name        string
	baseName    string
	suiteID     SuiteID
	allowLegacy bool
}

func newHybridEngine(kem KEM, suite Suite, allowLegacy bool) *HybridEngine {
	return &HybridEngine{
		kem:         kem,
		name:        suite.Name,
		baseName:    suite.KEMName,
		suiteID:     suite.ID,
		allowLegacy: allowLegacy,
	}
}

func (h *HybridEngine) SuiteID() SuiteID                    { return h.suiteID }
func (h *HybridEngine) Name() string                        { return h.name }
func (h *HybridEngine) BaseName() string                    { return h.baseName }
func (h *HybridEngine) GetPublicKey() []byte                { return h.kem.PublicKey() }
func (h *HybridEngine) IsMock() bool                        { return h.kem.IsMock() }
func (h *HybridEngine) ExportKeys() ([]byte, []byte, error) { return h.kem.ExportKeys() }

func (h *HybridEngine) algoForUsage(usage CryptoUsage) string {
	if usage == UsageKeyAgreement {
		return h.baseName
	}
	return h.name
}

// deriveSecret centralise la séquence transcript + domaine + KDF selon un invariant cryptographique strict.
func (h *HybridEngine) deriveSecret(rawSecret []byte, usage CryptoUsage, encapKey, recipientPK []byte) ([]byte, error) {
	algo := h.algoForUsage(usage)
	salt := BuildTranscriptSalt(algo, usage, encapKey, recipientPK)
	return DeriveSymmetricKey(rawSecret, salt, BuildDomainContext(algo, usage))
}

// Seal réalise l'encapsulation KEM et le chiffrement AEAD avec liaison transcript et séparation d'usage.
func (h *HybridEngine) Seal(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage) (*SealedPayload, error) {
	if err := validateUsagePayload(plaintext, usage); err != nil {
		return nil, err
	}

	effectivePK := recipientPK
	if len(effectivePK) == 0 {
		effectivePK = h.kem.PublicKey()
	}

	encapKey, sharedSecret, err := h.kem.Encapsulate(ctx, recipientPK)
	if err != nil {
		return nil, err
	}
	defer Zeroize(sharedSecret)

	symKey, err := h.deriveSecret(sharedSecret, usage, encapKey, effectivePK)
	if err != nil {
		return nil, fmt.Errorf("dérivation symétrique: %w", err)
	}
	defer Zeroize(symKey)

	aad := BuildAAD(h.name, usage, encapKey, effectivePK)
	nonce, ciphertext, err := EncryptSymmetric(symKey, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("chiffrement symétrique: %w", err)
	}

	return &SealedPayload{
		Algorithm:       h.name,
		Version:         ProtocolVersion,
		SuiteID:         h.suiteID,
		EncapsulatedKey: encapKey,
		Nonce:           nonce,
		Data:            ciphertext,
	}, nil
}

// Open réalise la décapsulation KEM et le déchiffrement AEAD avec vérification stricte du domaine d'usage.
func (h *HybridEngine) Open(ctx context.Context, payload *SealedPayload, usage CryptoUsage) ([]byte, error) {
	if payload == nil || len(payload.EncapsulatedKey) == 0 || len(payload.Nonce) == 0 || len(payload.Data) == 0 {
		return nil, fmt.Errorf("%w: charge utile scellée incomplète ou corrompue", ErrInvalidKey)
	}

	if err := ValidateEnvelopeMeta(EnvelopeMetadata{
		Version:   payload.Version,
		SuiteID:   payload.SuiteID,
		Algorithm: payload.Algorithm,
	}, h.suiteID, h.name, h.allowLegacy); err != nil {
		return nil, err
	}

	sharedSecret, err := h.kem.Decapsulate(ctx, payload.EncapsulatedKey)
	if err != nil {
		return nil, err
	}
	defer Zeroize(sharedSecret)

	effectivePK := h.kem.PublicKey()
	symKey, err := h.deriveSecret(sharedSecret, usage, payload.EncapsulatedKey, effectivePK)
	if err != nil {
		return nil, fmt.Errorf("dérivation symétrique: %w", err)
	}
	defer Zeroize(symKey)

	aad := BuildAAD(h.name, usage, payload.EncapsulatedKey, effectivePK)
	plaintext, err := DecryptSymmetric(symKey, payload.Nonce, payload.Data, aad)
	if err != nil {
		return nil, err
	}

	if err := validateUsagePayload(plaintext, usage); err != nil {
		Zeroize(plaintext)
		return nil, err
	}

	return plaintext, nil
}

func (h *HybridEngine) GenerateDataKey(ctx context.Context, keyLength int, recipientPK []byte) ([]byte, *SealedPayload, error) {
	if keyLength <= 0 {
		keyLength = 32
	}
	if err := validateKeyLength(keyLength); err != nil {
		return nil, nil, err
	}
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("génération entropie clé: %w", err)
	}
	wrapped, err := WrapKey(ctx, h, key, recipientPK)
	if err != nil {
		Zeroize(key)
		return nil, nil, err
	}
	return key, wrapped, nil
}

func (h *HybridEngine) Encapsulate(ctx context.Context, recipientPK []byte) (*KeyAgreementResult, error) {
	effectivePK := recipientPK
	if len(effectivePK) == 0 {
		effectivePK = h.kem.PublicKey()
	}

	encapKey, rawSecret, err := h.kem.Encapsulate(ctx, recipientPK)
	if err != nil {
		return nil, err
	}
	defer Zeroize(rawSecret)

	derivedSecret, err := h.deriveSecret(rawSecret, UsageKeyAgreement, encapKey, effectivePK)
	if err != nil {
		return nil, fmt.Errorf("dérivation secret d'accord de clé: %w", err)
	}

	return &KeyAgreementResult{
		Algorithm:       h.baseName,
		EncapsulatedKey: encapKey,
		SharedSecret:    derivedSecret,
	}, nil
}

func (h *HybridEngine) Decapsulate(ctx context.Context, encapsulatedKey []byte) ([]byte, error) {
	if len(encapsulatedKey) == 0 {
		return nil, fmt.Errorf("%w: clé encapsulée vide", ErrInvalidKey)
	}

	rawSecret, err := h.kem.Decapsulate(ctx, encapsulatedKey)
	if err != nil {
		return nil, err
	}
	defer Zeroize(rawSecret)

	effectivePK := h.kem.PublicKey()
	return h.deriveSecret(rawSecret, UsageKeyAgreement, encapsulatedKey, effectivePK)
}

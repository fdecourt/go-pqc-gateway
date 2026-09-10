package crypto

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrInvalidKey                = errors.New("clé cryptographique invalide")
	ErrDecapsulationFailed       = errors.New("échec de la décapsulation de la clé post-quantique")
	ErrDecryptionFailed          = errors.New("échec du déchiffrement des données (altération ou clé erronée)")
	ErrEmptyPayload              = errors.New("la charge utile à traiter ne peut pas être vide")
	ErrInvalidPayloadSize        = errors.New("longueur de charge utile invalide pour cet usage")
	ErrUnsupportedAlgorithm      = errors.New("algorithme cryptographique non supporté")
	ErrMismatchedSuite           = errors.New("identifiant de suite cryptographique non concordant")
	ErrMismatchedVersion         = errors.New("version de protocole cryptographique non concordante")
	ErrLegacyEnvelopesNotAllowed = errors.New("format binaire V2 requis (enveloppes sans en-tête 'PQ' désactivées)")
)

// EnvelopeMetadata regroupe les métadonnées d'une enveloppe cryptographique à valider.
type EnvelopeMetadata struct {
	Version   string
	SuiteID   SuiteID
	Algorithm string
}

// ValidateEnvelopeMeta centralise la règle de sécurité canonique de validation d'enveloppe (DRY).
func ValidateEnvelopeMeta(meta EnvelopeMetadata, expectedSuite SuiteID, expectedName string, allowLegacy bool) error {
	if meta.SuiteID != SuiteUnknown && meta.SuiteID != expectedSuite {
		return fmt.Errorf("%w: suite_id reçu (0x%04X) != actif (0x%04X)", ErrMismatchedSuite, uint16(meta.SuiteID), uint16(expectedSuite))
	}
	if meta.Version != "" && meta.Version != ProtocolVersion {
		return fmt.Errorf("%w: version reçue '%s' != attendue '%s'", ErrMismatchedVersion, meta.Version, ProtocolVersion)
	}
	if !allowLegacy && (meta.SuiteID == SuiteUnknown || meta.Version == "") {
		return fmt.Errorf("%w: les champs 'version' et 'suite_id' sont obligatoires", ErrInvalidKey)
	}
	if meta.Algorithm != "" {
		if !allowLegacy {
			if meta.Algorithm != expectedName {
				return fmt.Errorf("%w: algorithme '%s' non canonique (attendu '%s')", ErrUnsupportedAlgorithm, meta.Algorithm, expectedName)
			}
		} else {
			s, err := LookupSuite(meta.Algorithm)
			if err != nil || s.ID != expectedSuite {
				return fmt.Errorf("%w: algorithme '%s' incompatible avec '%s'", ErrUnsupportedAlgorithm, meta.Algorithm, expectedName)
			}
		}
	}
	return nil
}

// SealedPayload contient le résultat d'un scellement cryptographique KEM+DEM.
type SealedPayload struct {
	Algorithm       string  `json:"algorithm"`
	Version         string  `json:"version,omitempty"`
	SuiteID         SuiteID `json:"suite_id,omitempty"`
	EncapsulatedKey []byte  `json:"encapsulated_key"`
	Nonce           []byte  `json:"nonce"`
	Data            []byte  `json:"data"`
}

type KeyAgreementResult struct {
	Algorithm       string `json:"algorithm"`
	EncapsulatedKey []byte `json:"encapsulated_key"`
	SharedSecret    []byte `json:"shared_secret"`
}

// Engine définit le contrat d'abstraction cryptographique complet du microservice (ISP).
type Engine interface {
	Name() string
	BaseName() string
	SuiteID() SuiteID
	GetPublicKey() []byte
	IsMock() bool

	Seal(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage) (*SealedPayload, error)
	Open(ctx context.Context, payload *SealedPayload, usage CryptoUsage) ([]byte, error)
	GenerateDataKey(ctx context.Context, keyLength int, recipientPK []byte) ([]byte, *SealedPayload, error)
	Encapsulate(ctx context.Context, recipientPK []byte) (*KeyAgreementResult, error)
	Decapsulate(ctx context.Context, encapsulatedKey []byte) ([]byte, error)
}

// Encrypt chiffre des données applicatives sous l'usage DATA_ENCRYPTION (fonction libre sur Engine).
func Encrypt(ctx context.Context, e Engine, plaintext, recipientPK []byte) (*SealedPayload, error) {
	return e.Seal(ctx, plaintext, recipientPK, UsageDataEncryption)
}

// Decrypt déchiffre une enveloppe cryptographique sous l'usage DATA_ENCRYPTION (fonction libre sur Engine).
func Decrypt(ctx context.Context, e Engine, payload *SealedPayload) ([]byte, error) {
	return e.Open(ctx, payload, UsageDataEncryption)
}

// WrapKey enveloppe une clé symétrique cliente DEK sous l'usage KEY_WRAPPING_DEK (fonction libre sur Engine).
func WrapKey(ctx context.Context, e Engine, plaintextKey, recipientPK []byte) (*SealedPayload, error) {
	return e.Seal(ctx, plaintextKey, recipientPK, UsageKeyWrapping)
}

// UnwrapKey déroule une enveloppe de clé DEK sous l'usage KEY_WRAPPING_DEK (fonction libre sur Engine).
func UnwrapKey(ctx context.Context, e Engine, encapKey, nonce, wrappedKey []byte) ([]byte, error) {
	return e.Open(ctx, &SealedPayload{
		Version:         ProtocolVersion,
		SuiteID:         e.SuiteID(),
		EncapsulatedKey: encapKey,
		Nonce:           nonce,
		Data:            wrappedKey,
	}, UsageKeyWrapping)
}

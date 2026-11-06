package crypto

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrInvalidKey           = errors.New("clé cryptographique invalide")
	ErrInvalidEnvelope      = errors.New("enveloppe cryptographique incomplète ou mal formée")
	ErrUnknownKey           = errors.New("enveloppe chiffrée pour une autre clé (kid inconnu)")
	ErrDecapsulationFailed  = errors.New("échec de la décapsulation de la clé post-quantique")
	ErrDecryptionFailed     = errors.New("échec du déchiffrement des données (altération ou clé erronée)")
	ErrEmptyPayload         = errors.New("la charge utile à traiter ne peut pas être vide")
	ErrInvalidPayloadSize   = errors.New("longueur de charge utile invalide pour cet usage")
	ErrUnsupportedAlgorithm = errors.New("algorithme cryptographique non supporté")
	ErrMismatchedSuite      = errors.New("identifiant de suite cryptographique non concordant")
	ErrMismatchedVersion    = errors.New("version de protocole cryptographique non concordante")
)

// EnvelopeMetadata regroupe les métadonnées d'une enveloppe cryptographique à valider.
type EnvelopeMetadata struct {
	Version   string
	SuiteID   SuiteID
	Algorithm string
}

// ValidateEnvelopeMeta vérifie qu'une enveloppe annonce la version et la suite du moteur actif.
// 'version' et 'suite_id' sont obligatoires ; 'algorithm', facultatif, doit être le nom canonique.
func ValidateEnvelopeMeta(meta EnvelopeMetadata, expectedSuite SuiteID, expectedName string) error {
	if meta.SuiteID == SuiteUnknown || meta.Version == "" {
		return fmt.Errorf("%w: les champs 'version' et 'suite_id' sont obligatoires", ErrInvalidEnvelope)
	}
	if meta.SuiteID != expectedSuite {
		return fmt.Errorf("%w: suite_id reçu (0x%04X) != actif (0x%04X)", ErrMismatchedSuite, uint16(meta.SuiteID), uint16(expectedSuite))
	}
	if meta.Version != ProtocolVersion {
		return fmt.Errorf("%w: version reçue '%s' != attendue '%s'", ErrMismatchedVersion, meta.Version, ProtocolVersion)
	}
	if meta.Algorithm != "" && meta.Algorithm != expectedName {
		return fmt.Errorf("%w: algorithme '%s' non canonique (attendu '%s')", ErrUnsupportedAlgorithm, meta.Algorithm, expectedName)
	}
	return nil
}

// SealedPayload contient le résultat d'un scellement cryptographique KEM+DEM.
type SealedPayload struct {
	Algorithm       string  `json:"algorithm"`
	Version         string  `json:"version,omitempty"`
	SuiteID         SuiteID `json:"suite_id,omitempty"`
	KeyID           string  `json:"kid,omitempty"`
	EncapsulatedKey []byte  `json:"encapsulated_key"`
	Nonce           []byte  `json:"nonce"`
	Data            []byte  `json:"data"`
	// Context est le contexte de chiffrement fourni par l'appelant à l'ouverture. Il n'est
	// jamais sérialisé avec l'enveloppe : l'application le reconstitue depuis ses propres données.
	Context []byte `json:"-"`
}

type KeyAgreementResult struct {
	Algorithm       string `json:"algorithm"`
	EncapsulatedKey []byte `json:"encapsulated_key"`
	SharedSecret    []byte `json:"shared_secret"`
}

// Describer expose l'identité du moteur actif.
type Describer interface {
	Name() string
	BaseName() string
	SuiteID() SuiteID
	GetPublicKey() []byte
	// KeyID identifie la clé publique locale (voir crypto.KeyID).
	KeyID() string
	IsMock() bool
}

// Sealer chiffre vers une clé publique (la clé locale si recipientPK est vide).
// SealInPlace consomme plaintext : le chiffré remplace le clair dans son tampon quand la
// capacité le permet (len + InPlaceSlack), sans copie intermédiaire du clair.
type Sealer interface {
	Seal(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage, encCtx []byte) (*SealedPayload, error)
	SealInPlace(ctx context.Context, plaintext, recipientPK []byte, usage CryptoUsage, encCtx []byte) (*SealedPayload, error)
	GenerateDataKey(ctx context.Context, keyLength int, recipientPK, encCtx []byte) ([]byte, *SealedPayload, error)
}

// Opener déchiffre une enveloppe avec la clé privée locale. OpenInPlace consomme
// payload.Data : le clair remplace le chiffré dans son tampon.
type Opener interface {
	Open(ctx context.Context, payload *SealedPayload, usage CryptoUsage) ([]byte, error)
	OpenInPlace(ctx context.Context, payload *SealedPayload, usage CryptoUsage) ([]byte, error)
}

// KeyAgreement expose l'accord de clé KEM direct, sans chiffrement de données.
type KeyAgreement interface {
	Encapsulate(ctx context.Context, recipientPK []byte) (*KeyAgreementResult, error)
	Decapsulate(ctx context.Context, encapsulatedKey []byte) ([]byte, error)
}

// Engine réunit les quatre rôles. Un consommateur qui n'a besoin que d'un rôle
// (le self-test : KeyAgreement) dépend de l'interface étroite correspondante.
type Engine interface {
	Describer
	Sealer
	Opener
	KeyAgreement
}

// Encrypt chiffre des données applicatives sous l'usage DATA_ENCRYPTION (fonction libre sur Engine).
func Encrypt(ctx context.Context, e Engine, plaintext, recipientPK []byte) (*SealedPayload, error) {
	return e.Seal(ctx, plaintext, recipientPK, UsageDataEncryption, nil)
}

// Decrypt déchiffre une enveloppe cryptographique sous l'usage DATA_ENCRYPTION (fonction libre sur Engine).
func Decrypt(ctx context.Context, e Engine, payload *SealedPayload) ([]byte, error) {
	return e.Open(ctx, payload, UsageDataEncryption)
}

// WrapKey enveloppe une clé symétrique cliente DEK sous l'usage KEY_WRAPPING_DEK (fonction libre sur Engine).
func WrapKey(ctx context.Context, e Engine, plaintextKey, recipientPK []byte) (*SealedPayload, error) {
	return e.Seal(ctx, plaintextKey, recipientPK, UsageKeyWrapping, nil)
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

package api

import (
	"errors"
	"time"

	"pq-crypto-service/internal/secmem"
)

// Les requêtes sont décodées par secmem.DecodeStrict : les champs Base64 et texte sont lus
// directement en []byte (secmem.Base64, secmem.Text), jamais en chaînes Go immuables, et les
// champs secrets sont effacés par wipe() à la fin du traitement.

// HealthResponse modélise la réponse du healthcheck.
type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Algorithm string    `json:"algorithm"`
	MockMode  bool      `json:"mock_mode"`
	Timestamp time.Time `json:"timestamp"`
	UptimeSec int64     `json:"uptime_seconds"`
}

// MinimalHealthResponse est la réponse de /health à une sonde TLS sans certificat client :
// l'état, sans rien qui décrive le service.
type MinimalHealthResponse struct {
	Status string `json:"status"`
}

// PublicKeyResponse modélise la réponse pour la distribution de la clé publique active.
type PublicKeyResponse struct {
	Algorithm    string `json:"algorithm"`
	PublicKey    string `json:"public_key"`
	KeyID        string `json:"kid"`
	KeySizeBytes int    `json:"key_size_bytes"`
}

// ErrorResponse modélise une erreur structurée renvoyée au client HTTP.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// EnvelopeMeta regroupe les métadonnées de protocole et de suite d'une enveloppe reçue.
type EnvelopeMeta struct {
	Algorithm string `json:"algorithm,omitempty"`
	Version   string `json:"version,omitempty"`
	SuiteID   uint16 `json:"suite_id,omitempty"`
	KeyID     string `json:"kid,omitempty"` // clé destinataire (crypto.KeyID) ; facultatif en entrée
}

// RecipientKeyPayload porte la clé publique destinataire facultative (Base64).
type RecipientKeyPayload struct {
	RecipientPublicKey secmem.Base64 `json:"recipient_public_key,omitempty"`
}

// EncryptionContextPayload porte le contexte de chiffrement facultatif du client (équivalent de
// l'« encryption context » d'un KMS). Il est lié au chiffré mais jamais stocké avec lui :
// l'application le reconstitue (identifiant d'enregistrement, locataire…) et doit le fournir
// à l'identique pour déchiffrer. Ce n'est pas un secret : n'y placer aucune donnée sensible.
type EncryptionContextPayload struct {
	Context string `json:"context,omitempty"`
}

// ContextBytes renvoie le contexte sous forme d'octets (nil s'il est absent).
func (p *EncryptionContextPayload) ContextBytes() []byte {
	if p.Context == "" {
		return nil
	}
	return []byte(p.Context)
}

// envelopeFields est la partie commune des requêtes d'ouverture d'enveloppe.
type envelopeFields struct {
	EnvelopeMeta
	EncryptionContextPayload
	EncapsulatedKey secmem.Base64 `json:"encapsulated_key"`
	Nonce           secmem.Base64 `json:"nonce"`
}

func (e *envelopeFields) complete(data []byte) error {
	if len(e.EncapsulatedKey) == 0 || len(e.Nonce) == 0 || len(data) == 0 {
		return errors.New("champs d'enveloppe incomplets")
	}
	return nil
}

// EncryptRequest modélise la requête de chiffrement : exactement un des champs 'data'
// (Base64, binaire) ou 'plaintext' (texte UTF-8).
type EncryptRequest struct {
	RecipientKeyPayload
	EncryptionContextPayload
	Plaintext secmem.Text   `json:"plaintext,omitempty"`
	Data      secmem.Base64 `json:"data,omitempty"`
}

// payload renvoie la charge à chiffrer (sans copie : elle reste effacée par wipe).
func (r *EncryptRequest) payload() ([]byte, error) {
	switch {
	case len(r.Data) > 0 && len(r.Plaintext) > 0:
		return nil, errors.New("renseigner un seul des champs 'plaintext' ou 'data'")
	case len(r.Data) > 0:
		return r.Data, nil
	case len(r.Plaintext) > 0:
		return r.Plaintext, nil
	default:
		return nil, errors.New("un des champs 'plaintext' ou 'data' doit être renseigné")
	}
}

func (r *EncryptRequest) wipe() { r.Plaintext.Wipe(); r.Data.Wipe() }

// DecryptRequest modélise l'enveloppe à déchiffrer.
type DecryptRequest struct {
	envelopeFields
	Ciphertext secmem.Base64 `json:"ciphertext"`
}

func (r *DecryptRequest) wipe() {}

// WrapKeyRequest modélise la requête pour envelopper une clé cliente (DEK).
type WrapKeyRequest struct {
	RecipientKeyPayload
	EncryptionContextPayload
	PlaintextKey secmem.Base64 `json:"plaintext_key"`
}

func (r *WrapKeyRequest) wipe() { r.PlaintextKey.Wipe() }

// UnwrapKeyRequest modélise la requête pour déchiffrer une clé enveloppée.
type UnwrapKeyRequest struct {
	envelopeFields
	WrappedKey secmem.Base64 `json:"wrapped_key"`
}

func (r *UnwrapKeyRequest) wipe() {}

// GenerateDataKeyRequest modélise la demande de génération d'une clé de données (DEK).
type GenerateDataKeyRequest struct {
	RecipientKeyPayload
	EncryptionContextPayload
	KeyLength int `json:"key_length,omitempty"`
}

func (r *GenerateDataKeyRequest) wipe() {}

// EncapsulateRequest modélise une demande d'encapsulation directe.
type EncapsulateRequest struct {
	RecipientKeyPayload
}

func (r *EncapsulateRequest) wipe() {}

// DecapsulateRequest modélise une demande de décapsulation directe.
type DecapsulateRequest struct {
	EncapsulatedKey secmem.Base64 `json:"encapsulated_key"`
}

func (r *DecapsulateRequest) wipe() {}

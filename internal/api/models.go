package api

import (
	"encoding/base64"
	"errors"
	"time"
	"unicode/utf8"
)

// HealthResponse modélise la réponse du healthcheck.
type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Algorithm string    `json:"algorithm"`
	MockMode  bool      `json:"mock_mode"`
	Timestamp time.Time `json:"timestamp"`
	UptimeSec int64     `json:"uptime_seconds"`
}

// PublicKeyResponse modélise la réponse pour la distribution de la clé publique active.
type PublicKeyResponse struct {
	Algorithm    string `json:"algorithm"`
	PublicKey    string `json:"public_key"`
	KeySizeBytes int    `json:"key_size_bytes"`
}

// EnvelopeMeta regroupe les métadonnées de protocole et de suite pour les requêtes et réponses chiffrées (DRY).
type EnvelopeMeta struct {
	Algorithm string `json:"algorithm,omitempty"`
	Version   string `json:"version,omitempty"`
	SuiteID   uint16 `json:"suite_id,omitempty"`
}

// RecipientKeyPayload porte le champ optionnel recipient_public_key et son décodage Base64 (DRY).
type RecipientKeyPayload struct {
	RecipientPublicKey string `json:"recipient_public_key,omitempty"`
}

func (p *RecipientKeyPayload) GetRecipientPK() ([]byte, error) {
	if p.RecipientPublicKey == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(p.RecipientPublicKey)
}

// decodeEnvelopeFields valide et décode de façon unifiée les trois composantes Base64 d'une enveloppe (DRY).
func decodeEnvelopeFields(encapB64, nonceB64, dataB64, name string) ([]byte, []byte, []byte, error) {
	if encapB64 == "" || nonceB64 == "" || dataB64 == "" {
		return nil, nil, nil, errors.New("champs d'enveloppe incomplets")
	}
	encapKey, err := base64.StdEncoding.DecodeString(encapB64)
	if err != nil {
		return nil, nil, nil, errors.New("champ 'encapsulated_key' Base64 invalide")
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, nil, nil, errors.New("champ 'nonce' Base64 invalide")
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, nil, nil, errors.New("champ '" + name + "' Base64 invalide")
	}
	return encapKey, nonce, data, nil
}

// EncryptRequest modélise la requête de chiffrement hybride.
type EncryptRequest struct {
	RecipientKeyPayload
	Plaintext string `json:"plaintext,omitempty"`
	Data      string `json:"data,omitempty"`
}

func (r *EncryptRequest) GetBytes() ([]byte, error) {
	if r.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil || len(decoded) == 0 {
			return nil, errors.New("charge utile 'data' vide ou Base64 invalide")
		}
		return decoded, nil
	}
	if r.Plaintext != "" {
		// NOTE ARCHITECTURALE (F1) : En Go, les chaînes 'string' sont immutables dans le tas.
		// La conversion []byte(r.Plaintext) alloue une copie modifiable, mais la chaîne sous-jacente
		// persiste jusqu'au prochain cycle GC. Pour un effacement strict (zeroization) sans copie en RAM,
		// privilégier le transport binaire 'application/octet-stream' ou le champ 'data' (Base64 décodé).
		return []byte(r.Plaintext), nil
	}
	return nil, errors.New("un des champs 'plaintext' ou 'data' doit être renseigné")
}

// EncryptResponse modélise la réponse du chiffrement hybride.
type EncryptResponse struct {
	EnvelopeMeta
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// DecryptRequest modélise la charge chiffrée à déchiffrer.
type DecryptRequest struct {
	EnvelopeMeta
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

func (r *DecryptRequest) Validate() ([]byte, []byte, []byte, error) {
	return decodeEnvelopeFields(r.EncapsulatedKey, r.Nonce, r.Ciphertext, "ciphertext")
}

// DecryptResponse modélise la réponse avec les données déchiffrées.
type DecryptResponse struct {
	Plaintext string `json:"plaintext,omitempty"`
	Data      string `json:"data"`
}

// NewDecryptResponse construit la réponse de déchiffrement JSON.
// NOTE DE SÉCURITÉ MÉMOIRE (F1) : L'encodage JSON impose des allocations immuables de type string
// ('Data' en Base64 et 'Plaintext' en UTF-8). Le zeroize des buffers bruts en aval n'efface donc
// pas ces chaînes gérées par le GC. Les environnements à très haute sensibilité cryptographique
// doivent utiliser le transport 'application/octet-stream' où les tranches d'octets sont nettoyées in situ.
func NewDecryptResponse(plaintextBytes []byte) *DecryptResponse {
	resp := &DecryptResponse{Data: base64.StdEncoding.EncodeToString(plaintextBytes)}
	if utf8.Valid(plaintextBytes) {
		resp.Plaintext = string(plaintextBytes)
	}
	return resp
}

// ErrorResponse modélise une erreur structurée renvoyée au client HTTP.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// WrapKeyRequest modélise la requête pour envelopper une clé cliente (DEK).
type WrapKeyRequest struct {
	RecipientKeyPayload
	PlaintextKey string `json:"plaintext_key"`
}

func (r *WrapKeyRequest) GetKeyBytes() ([]byte, error) {
	if r.PlaintextKey == "" {
		return nil, errors.New("champ 'plaintext_key' manquant (clé Base64 requise)")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(r.PlaintextKey)
	if err != nil {
		return nil, errors.New("champ 'plaintext_key' contient du Base64 invalide")
	}
	return keyBytes, nil
}

// WrapKeyResponse modélise l'enveloppe cryptographique post-quantique retournée.
type WrapKeyResponse struct {
	EnvelopeMeta
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

// UnwrapKeyRequest modélise la requête pour déchiffrer une clé enveloppée.
type UnwrapKeyRequest struct {
	EnvelopeMeta
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

func (r *UnwrapKeyRequest) Validate() ([]byte, []byte, []byte, error) {
	return decodeEnvelopeFields(r.EncapsulatedKey, r.Nonce, r.WrappedKey, "wrapped_key")
}

// UnwrapKeyResponse restitue la clé cliente déchiffrée en Base64.
type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"`
	KeyLength    int    `json:"key_length"`
}

// GenerateDataKeyRequest modélise la demande de génération KMS d'une clé DEK.
type GenerateDataKeyRequest struct {
	RecipientKeyPayload
	KeyLength int `json:"key_length,omitempty"`
}

// GenerateDataKeyResponse fournit la clé en clair ET son enveloppe chiffrée.
type GenerateDataKeyResponse struct {
	EnvelopeMeta
	PlaintextKey    string `json:"plaintext_key"`
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

// EncapsulateRequest modélise une demande d'encapsulation directe.
type EncapsulateRequest struct {
	RecipientKeyPayload
}

// EncapsulateResponse retourne le ciphertext KEM et le secret partagé calculé.
type EncapsulateResponse struct {
	Algorithm       string `json:"algorithm"`
	EncapsulatedKey string `json:"encapsulated_key"`
	SharedSecret    string `json:"shared_secret"`
}

// DecapsulateRequest modélise une demande de décapsulation directe.
type DecapsulateRequest struct {
	EncapsulatedKey string `json:"encapsulated_key"`
}

func (r *DecapsulateRequest) GetKeyBytes() ([]byte, error) {
	if r.EncapsulatedKey == "" {
		return nil, errors.New("champ 'encapsulated_key' manquant")
	}
	bytes, err := base64.StdEncoding.DecodeString(r.EncapsulatedKey)
	if err != nil || len(bytes) == 0 {
		return nil, errors.New("champ 'encapsulated_key' Base64 invalide")
	}
	return bytes, nil
}

// DecapsulateResponse retourne le secret partagé récupéré.
type DecapsulateResponse struct {
	Algorithm    string `json:"algorithm"`
	SharedSecret string `json:"shared_secret"`
}

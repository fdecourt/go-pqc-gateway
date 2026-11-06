package tests

// Types « fil » du contrat JSON de l'API, côté client. Les tests boîte noire ne réutilisent
// pas les types internes du serveur : un écart de contrat (nom ou forme de champ) les fait échouer.

type EnvelopeMeta struct {
	Algorithm string `json:"algorithm,omitempty"`
	Version   string `json:"version,omitempty"`
	SuiteID   uint16 `json:"suite_id,omitempty"`
	KeyID     string `json:"kid,omitempty"` // clé destinataire (crypto.KeyID) ; facultatif en entrée
}

type RecipientKeyPayload struct {
	RecipientPublicKey string `json:"recipient_public_key,omitempty"`
}

type EncryptionContextPayload struct {
	Context string `json:"context,omitempty"`
}

type EncryptRequest struct {
	RecipientKeyPayload
	EncryptionContextPayload
	Plaintext string `json:"plaintext,omitempty"`
	Data      string `json:"data,omitempty"`
}

type EncryptResponse struct {
	EnvelopeMeta
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

type DecryptRequest struct {
	EnvelopeMeta
	EncryptionContextPayload
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext,omitempty"`
	Data      string `json:"data,omitempty"`
}

type WrapKeyRequest struct {
	RecipientKeyPayload
	EncryptionContextPayload
	PlaintextKey string `json:"plaintext_key"`
}

type WrapKeyResponse struct {
	EnvelopeMeta
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

type UnwrapKeyRequest struct {
	EnvelopeMeta
	EncryptionContextPayload
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"`
	KeyLength    int    `json:"key_length"`
}

type GenerateDataKeyRequest struct {
	RecipientKeyPayload
	EncryptionContextPayload
	KeyLength int `json:"key_length,omitempty"`
}

type GenerateDataKeyResponse struct {
	EnvelopeMeta
	PlaintextKey    string `json:"plaintext_key"`
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

type EncapsulateRequest struct {
	RecipientKeyPayload
}

type EncapsulateResponse struct {
	Algorithm       string `json:"algorithm"`
	EncapsulatedKey string `json:"encapsulated_key"`
	SharedSecret    string `json:"shared_secret"`
}

type DecapsulateRequest struct {
	EncapsulatedKey string `json:"encapsulated_key"`
}

type DecapsulateResponse struct {
	Algorithm    string `json:"algorithm"`
	SharedSecret string `json:"shared_secret"`
}

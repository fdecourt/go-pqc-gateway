package api

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"unicode/utf8"

	"pq-crypto-service/internal/crypto"
	"pq-crypto-service/internal/secmem"
)

const jsonContentType = "application/json; charset=utf-8"

// streamThreshold : au-delà de cette taille de champ, la réponse est écrite en flux ; en
// deçà, un seul tampon et une seule écriture reviennent moins cher que des blocs.
const streamThreshold = 16 << 10

// envelopeOverhead majore la taille JSON d'une enveloppe hors champs Base64 (noms et métadonnées).
const envelopeOverhead = 256

func b64Len(b []byte) int { return base64.StdEncoding.EncodedLen(len(b)) }

// writeEnvelopeMeta écrit les métadonnées d'une enveloppe, dans l'ordre historique de l'API.
func writeEnvelopeMeta(o *secmem.JSONObject, p *crypto.SealedPayload) {
	o.StringOmitEmpty("algorithm", p.Algorithm)
	o.StringOmitEmpty("version", p.Version)
	o.UintOmitZero("suite_id", uint64(p.SuiteID))
	o.StringOmitEmpty("kid", p.KeyID)
}

// beginStreamedJSON envoie les en-têtes d'une réponse JSON dont le corps est : prefix,
// puis bodyLen octets écrits en flux, puis "}\n". Les gros champs ne sont jamais copiés
// dans un tampon de réponse : ils sont encodés par blocs de pile directement vers la connexion.
func beginStreamedJSON(w http.ResponseWriter, prefix *secmem.Buffer, bodyLen int) {
	defer prefix.Wipe()
	setContentType(w, jsonContentType)
	w.Header().Set("Content-Length", strconv.Itoa(prefix.Len()+bodyLen+len("}\n")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(prefix.Bytes()) // #nosec G104 -- en-têtes envoyés : une erreur d'écriture n'a plus de destinataire
}

func endStreamedJSON(w http.ResponseWriter) { _, _ = w.Write([]byte("}\n")) }

// respondEnvelope renvoie une enveloppe ; dataField nomme le chiffré ("ciphertext", "wrapped_key").
// Les métadonnées, la clé encapsulée et le nonce tiennent dans un petit tampon effaçable ;
// le chiffré est encodé en Base64 en flux.
func respondEnvelope(w http.ResponseWriter, p *crypto.SealedPayload, dataField string) {
	if len(p.Data) <= streamThreshold {
		o := secmem.NewJSONObject(envelopeOverhead + b64Len(p.EncapsulatedKey) + b64Len(p.Nonce) + b64Len(p.Data))
		writeEnvelopeMeta(o, p)
		o.Base64("encapsulated_key", p.EncapsulatedKey)
		o.Base64("nonce", p.Nonce)
		o.Base64(dataField, p.Data)
		respondBuffer(w, http.StatusOK, jsonContentType, o.FinishLine())
		return
	}
	o := secmem.NewJSONObject(envelopeOverhead + b64Len(p.EncapsulatedKey) + b64Len(p.Nonce))
	writeEnvelopeMeta(o, p)
	o.Base64("encapsulated_key", p.EncapsulatedKey)
	o.Base64("nonce", p.Nonce)
	prefix := o.OpenField(dataField)
	beginStreamedJSON(w, prefix, b64Len(p.Data)+2)
	_, _ = w.Write([]byte{'"'})
	_ = secmem.StreamBase64(w, p.Data)
	_, _ = w.Write([]byte{'"'})
	endStreamedJSON(w)
}

// textEscapeAllowance est le surcoût d'échappement toléré au-delà de la taille Base64 pour
// renvoyer un clair UTF-8 sous forme de texte.
const textEscapeAllowance = 4 << 10

// respondPlaintext renvoie un clair déchiffré dans exactement un champ : 'plaintext' s'il est
// de l'UTF-8 valide et que son encodage JSON ne dépasse pas la taille Base64 de plus de
// textEscapeAllowance, 'data' (Base64) sinon. La borne évite qu'un clair truffé de caractères
// à échapper (jusqu'à 6 octets par octet) ne fasse exploser la réponse et le budget mémoire.
// Le clair est encodé en flux, jamais recopié dans un tampon de réponse.
func respondPlaintext(w http.ResponseWriter, plaintext []byte) {
	if utf8.Valid(plaintext) {
		if n := secmem.JSONStringLen(plaintext); n <= b64Len(plaintext)+2+textEscapeAllowance {
			if len(plaintext) <= streamThreshold {
				o := secmem.NewJSONObject(n + 16)
				o.Text("plaintext", plaintext)
				respondBuffer(w, http.StatusOK, jsonContentType, o.FinishLine())
				return
			}
			beginStreamedJSON(w, secmem.NewJSONObject(32).OpenField("plaintext"), n)
			_ = secmem.StreamJSONString(w, plaintext)
			endStreamedJSON(w)
			return
		}
	}
	if len(plaintext) <= streamThreshold {
		o := secmem.NewJSONObject(b64Len(plaintext) + 16)
		o.Base64("data", plaintext)
		respondBuffer(w, http.StatusOK, jsonContentType, o.FinishLine())
		return
	}
	beginStreamedJSON(w, secmem.NewJSONObject(32).OpenField("data"), b64Len(plaintext)+2)
	_, _ = w.Write([]byte{'"'})
	_ = secmem.StreamBase64(w, plaintext)
	_, _ = w.Write([]byte{'"'})
	endStreamedJSON(w)
}

// respondUnwrappedKey renvoie une clé de données déchiffrée.
func respondUnwrappedKey(w http.ResponseWriter, key []byte) {
	o := secmem.NewJSONObject(b64Len(key) + 64)
	o.Base64("plaintext_key", key)
	o.Int("key_length", int64(len(key)))
	respondBuffer(w, http.StatusOK, jsonContentType, o.FinishLine())
}

// respondDataKey renvoie une clé de données en clair et son enveloppe.
func respondDataKey(w http.ResponseWriter, key []byte, p *crypto.SealedPayload) {
	o := secmem.NewJSONObject(envelopeOverhead + b64Len(key) + b64Len(p.EncapsulatedKey) + b64Len(p.Nonce) + b64Len(p.Data))
	writeEnvelopeMeta(o, p)
	o.Base64("plaintext_key", key)
	o.Base64("encapsulated_key", p.EncapsulatedKey)
	o.Base64("nonce", p.Nonce)
	o.Base64("wrapped_key", p.Data)
	respondBuffer(w, http.StatusOK, jsonContentType, o.FinishLine())
}

// respondSharedSecret renvoie le résultat d'un accord de clé (encapKey nil : décapsulation).
func respondSharedSecret(w http.ResponseWriter, algorithm string, encapKey, secret []byte) {
	o := secmem.NewJSONObject(envelopeOverhead + b64Len(encapKey) + b64Len(secret))
	o.String("algorithm", algorithm)
	if encapKey != nil {
		o.Base64("encapsulated_key", encapKey)
	}
	o.Base64("shared_secret", secret)
	respondBuffer(w, http.StatusOK, jsonContentType, o.FinishLine())
}

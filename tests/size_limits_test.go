package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

// sizeLimitPayload est la limite de corps utilisée par ces tests : assez grande pour être
// représentative, assez petite pour rester rapide.
const sizeLimitPayload = 256 << 10

func newLimitRouter(t *testing.T, suite string) http.Handler {
	t.Helper()
	engine, err := crypto.NewEngineForSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	r := api.NewRouter(&config.Config{Port: 8080, MaxPayloadBytes: sizeLimitPayload}, engine)
	t.Cleanup(r.Close)
	return r
}

func post(router http.Handler, path, contentType string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// jsonBodyOfSize renvoie un corps /encrypt d'exactement size octets (champ field), et le clair.
func jsonBodyOfSize(t *testing.T, field string, size int) ([]byte, []byte) {
	t.Helper()
	overhead := len(`{"` + field + `":""}`)
	var plain []byte
	var value string
	if field == "data" {
		n := (size - overhead) / 4 * 3
		plain = make([]byte, n)
		_, _ = rand.Read(plain)
		value = base64.StdEncoding.EncodeToString(plain)
	} else {
		plain = bytes.Repeat([]byte("a"), size-overhead)
		value = string(plain)
	}
	body := []byte(`{"` + field + `":"` + value + `"}`)
	if len(body) > size {
		t.Fatalf("corps de %d octets > %d", len(body), size)
	}
	return body, plain
}

// TestLimits_MaxSizeRoundTrip garantit qu'un chiffré produit à la taille maximale admise par
// /encrypt est toujours accepté par /decrypt, pour chaque suite et chaque transport.
func TestLimits_MaxSizeRoundTrip(t *testing.T) {
	for _, suite := range []string{"ML-KEM-768", "ML-KEM-1024", "DUAL-X25519+ML-KEM-768", "DUAL-X25519+ML-KEM-1024"} {
		router := newLimitRouter(t, suite)

		for _, field := range []string{"data", "plaintext"} {
			t.Run(suite+"/json-"+field, func(t *testing.T) {
				body, plain := jsonBodyOfSize(t, field, sizeLimitPayload)
				enc := post(router, "/encrypt", "application/json", body)
				if enc.Code != http.StatusOK {
					t.Fatalf("/encrypt: %d %s", enc.Code, enc.Body.String())
				}
				encBytes := enc.Body.Bytes()

				// Tel quel, puis réencodé par un client qui échappe les « / » (json_encode de PHP).
				for name, envelope := range map[string][]byte{
					"tel quel":      encBytes,
					"slash échappé": bytes.ReplaceAll(encBytes, []byte("/"), []byte(`\/`)),
				} {
					dec := post(router, "/decrypt", "application/json", envelope)
					if dec.Code != http.StatusOK {
						t.Fatalf("/decrypt (%s, corps %d octets): %d %s", name, len(envelope), dec.Code, dec.Body.String())
					}
					var out DecryptResponse
					if err := json.Unmarshal(dec.Body.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					got := []byte(out.Plaintext)
					if out.Data != "" {
						got, _ = base64.StdEncoding.DecodeString(out.Data)
					}
					if !bytes.Equal(got, plain) {
						t.Fatalf("/decrypt (%s): clair différent", name)
					}
				}
			})
		}

		t.Run(suite+"/binaire", func(t *testing.T) {
			plain := make([]byte, sizeLimitPayload)
			_, _ = rand.Read(plain)
			enc := post(router, "/encrypt", "application/octet-stream", plain)
			if enc.Code != http.StatusOK {
				t.Fatalf("/encrypt binaire: %d %s", enc.Code, enc.Body.String())
			}
			dec := post(router, "/decrypt", "application/octet-stream", enc.Body.Bytes())
			if dec.Code != http.StatusOK || !bytes.Equal(dec.Body.Bytes(), plain) {
				t.Fatalf("/decrypt binaire: %d", dec.Code)
			}
		})
	}
}

// TestLimits_PerRoute vérifie que seules /encrypt et /decrypt acceptent de gros corps.
func TestLimits_PerRoute(t *testing.T) {
	router := newLimitRouter(t, "ML-KEM-768")

	over := func(limit int) []byte { return []byte(`{"plaintext":"` + strings.Repeat("a", limit) + `"}`) }
	if rr := post(router, "/encrypt", "application/json", over(sizeLimitPayload)); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("/encrypt au-delà de la limite: attendu 413, obtenu %d", rr.Code)
	}
	for _, path := range []string{"/wrap-key", "/unwrap-key", "/generate-key", "/kem/encapsulate", "/kem/decapsulate"} {
		if rr := post(router, path, "application/json", over(api.SmallBodyLimit)); rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s au-delà de SmallBodyLimit: attendu 413, obtenu %d", path, rr.Code)
		}
	}
	if rr := post(router, "/decrypt", "application/json", over(int(api.OpenBodyLimit(sizeLimitPayload)))); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("/decrypt au-delà de sa limite: attendu 413, obtenu %d", rr.Code)
	}
}

// TestLimits_EscapeHeavyPlaintextFallsBackToBase64 vérifie qu'un clair UTF-8 coûteux à
// échapper est renvoyé en Base64 : la réponse reste bornée à 4/3 du clair.
func TestLimits_EscapeHeavyPlaintextFallsBackToBase64(t *testing.T) {
	router := newLimitRouter(t, "ML-KEM-768")
	plain := bytes.Repeat([]byte{0x01}, 16<<10) // UTF-8 valide, 6 octets JSON par octet
	enc := post(router, "/encrypt", "application/json", []byte(`{"data":"`+base64.StdEncoding.EncodeToString(plain)+`"}`))
	if enc.Code != http.StatusOK {
		t.Fatalf("/encrypt: %d %s", enc.Code, enc.Body.String())
	}
	dec := post(router, "/decrypt", "application/json", enc.Body.Bytes())
	var out DecryptResponse
	if err := json.Unmarshal(dec.Body.Bytes(), &out); err != nil || dec.Code != http.StatusOK {
		t.Fatalf("/decrypt: %d %v", dec.Code, err)
	}
	if out.Plaintext != "" || out.Data != base64.StdEncoding.EncodeToString(plain) {
		t.Fatal("un clair à fort coût d'échappement doit être renvoyé dans 'data'")
	}
	if dec.Body.Len() > base64.StdEncoding.EncodedLen(len(plain))+64 {
		t.Fatalf("réponse non bornée: %d octets", dec.Body.Len())
	}

	text := "texte <ordinaire> & accentué : é"
	enc = post(router, "/encrypt", "application/json", []byte(`{"plaintext":"`+text+`"}`))
	dec = post(router, "/decrypt", "application/json", enc.Body.Bytes())
	if err := json.Unmarshal(dec.Body.Bytes(), &out); err != nil || out.Plaintext != text {
		t.Fatalf("texte ordinaire: attendu 'plaintext', obtenu %s", dec.Body.String())
	}
}

// TestStrictJSON_Rejections vérifie le décodage strict des requêtes.
func TestStrictJSON_Rejections(t *testing.T) {
	router := newLimitRouter(t, "ML-KEM-768")
	for name, body := range map[string]string{
		"champ inconnu":        `{"plaintext":"x","extra":1}`,
		"casse différente":     `{"Plaintext":"x"}`,
		"doublon":              `{"plaintext":"x","plaintext":"y"}`,
		"deux charges":         `{"plaintext":"x","data":"eA=="}`,
		"base64 non canonique": `{"data":"eB=="}`,
		"second document":      `{"plaintext":"x"}{}`,
	} {
		if rr := post(router, "/encrypt", "application/json", []byte(body)); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: attendu 400, obtenu %d (%s)", name, rr.Code, rr.Body.String())
		}
	}
}

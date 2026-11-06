package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/crypto"
)

// TestEncryptionContext_Engine vérifie que le contexte est lié au chiffré : il faut le même
// contexte pour ouvrir, son absence ou sa modification échouent comme une altération.
func TestEncryptionContext_Engine(t *testing.T) {
	ctx := context.Background()
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}
	encCtx := []byte(`tenant=acme;record=42`)

	for _, usage := range []crypto.CryptoUsage{crypto.UsageDataEncryption, crypto.UsageKeyWrapping} {
		sealed, err := engine.Seal(ctx, bytes.Repeat([]byte{7}, 32), nil, usage, encCtx)
		if err != nil {
			t.Fatalf("%s: seal: %v", usage, err)
		}

		sealed.Context = encCtx
		if _, err := engine.Open(ctx, sealed, usage); err != nil {
			t.Fatalf("%s: ouverture avec le bon contexte refusée: %v", usage, err)
		}
		for _, wrong := range [][]byte{nil, []byte(`tenant=acme;record=43`)} {
			sealed.Context = wrong
			if _, err := engine.Open(ctx, sealed, usage); !errors.Is(err, crypto.ErrDecryptionFailed) {
				t.Fatalf("%s: contexte %q accepté (err=%v)", usage, wrong, err)
			}
		}
	}

	// Une enveloppe sans contexte ne s'ouvre pas si l'on en invente un.
	plain, err := crypto.Encrypt(ctx, engine, []byte("sans contexte"), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain.Context = encCtx
	if _, err := crypto.Decrypt(ctx, engine, plain); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("contexte ajouté à l'ouverture accepté (err=%v)", err)
	}

	tooBig := bytes.Repeat([]byte{'x'}, crypto.MaxEncryptionContextSize+1)
	if _, err := engine.Seal(ctx, []byte("x"), nil, crypto.UsageDataEncryption, tooBig); !errors.Is(err, crypto.ErrInvalidPayloadSize) {
		t.Fatalf("contexte surdimensionné accepté (err=%v)", err)
	}
}

// TestEncryptionContext_API vérifie le champ JSON "context" et l'en-tête binaire X-Encryption-Context.
func TestEncryptionContext_API(t *testing.T) {
	router, _ := setupTestServer(t)
	post := func(path string, body []byte, contentType string, header map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// JSON
	encBody, _ := json.Marshal(EncryptRequest{
		Plaintext:                "dossier médical",
		EncryptionContextPayload: EncryptionContextPayload{Context: "patient=1234"},
	})
	rr := post("/encrypt", encBody, "application/json", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("/encrypt avec contexte: %d %s", rr.Code, rr.Body.String())
	}
	var enc EncryptResponse
	_ = json.NewDecoder(rr.Body).Decode(&enc)
	if strings.Contains(rr.Body.String(), "patient=1234") {
		t.Fatal("le contexte ne doit pas être renvoyé avec l'enveloppe")
	}

	decrypt := func(contextValue string) int {
		body, _ := json.Marshal(DecryptRequest{
			EnvelopeMeta:             enc.EnvelopeMeta,
			EncryptionContextPayload: EncryptionContextPayload{Context: contextValue},
			EncapsulatedKey:          enc.EncapsulatedKey,
			Nonce:                    enc.Nonce,
			Ciphertext:               enc.Ciphertext,
		})
		return post("/decrypt", body, "application/json", nil).Code
	}
	if code := decrypt("patient=1234"); code != http.StatusOK {
		t.Fatalf("/decrypt avec le bon contexte: %d", code)
	}
	for _, wrong := range []string{"", "patient=9999"} {
		if code := decrypt(wrong); code != http.StatusUnprocessableEntity {
			t.Fatalf("/decrypt avec contexte %q: attendu 422, obtenu %d", wrong, code)
		}
	}

	// Binaire
	hdr := map[string]string{api.EncryptionContextHeader: "patient=1234"}
	rrBin := post("/encrypt", []byte("binaire"), "application/octet-stream", hdr)
	if rrBin.Code != http.StatusOK {
		t.Fatalf("/encrypt binaire avec contexte: %d", rrBin.Code)
	}
	envelope := rrBin.Body.Bytes()
	if rr := post("/decrypt", envelope, "application/octet-stream", hdr); rr.Code != http.StatusOK || rr.Body.String() != "binaire" {
		t.Fatalf("/decrypt binaire avec le bon contexte: %d %q", rr.Code, rr.Body.String())
	}
	if rr := post("/decrypt", envelope, "application/octet-stream", nil); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("/decrypt binaire sans contexte: attendu 422, obtenu %d", rr.Code)
	}
}

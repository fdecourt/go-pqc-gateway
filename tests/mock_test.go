//go:build mock

// Tests du moteur simulé. Le mode mock n'est compilé qu'avec le build tag "mock"
// (go test -tags mock ./...) : il est absent du binaire livré.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

func TestMockEngine_Roundtrip(t *testing.T) {
	mock := crypto.NewMockEngine()
	if !mock.IsMock() {
		t.Fatal("MockEngine.IsMock() doit être true")
	}

	ctx := context.Background()
	testMsg := []byte("Test avec le moteur Mock")

	payload, err := crypto.Encrypt(ctx, mock, testMsg, nil)
	if err != nil {
		t.Fatalf("erreur mock encrypt: %v", err)
	}

	decrypted, err := crypto.Decrypt(ctx, mock, payload)
	if err != nil {
		t.Fatalf("erreur mock decrypt: %v", err)
	}

	if !bytes.Equal(testMsg, decrypted) {
		t.Fatalf("mock decrypt mismatch")
	}
}

func BenchmarkMock_HybridRoundtrip(b *testing.B) {
	mock := crypto.NewMockEngine()
	ctx := context.Background()
	plaintext := []byte("Benchmark payload for mock")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		payload, err := crypto.Encrypt(ctx, mock, plaintext, nil)
		if err != nil {
			b.Fatalf("mock encrypt error: %v", err)
		}
		_, err = crypto.Decrypt(ctx, mock, payload)
		if err != nil {
			b.Fatalf("mock decrypt error: %v", err)
		}
	}
}

func TestEnvelope_MockMode_StrictRoundtrip(t *testing.T) {
	cfg := &config.Config{
		Port:            8080,
		MaxPayloadBytes: 10 * 1024 * 1024,
	}
	mockEngine := crypto.NewMockEngine()
	if mockEngine.SuiteID() != crypto.SuiteMock {
		t.Fatalf("MockEngine SuiteID attendu 0x%04X, obtenu 0x%04X", uint16(crypto.SuiteMock), uint16(mockEngine.SuiteID()))
	}
	router := api.NewRouter(cfg, mockEngine)

	testMsg := []byte("Message en mode Mock sous contrôle strict d'enveloppe")
	reqEnc := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader([]byte(`{"plaintext":"`+string(testMsg)+`"}`)))
	reqEnc.Header.Set("Content-Type", "application/json")
	rrEnc := httptest.NewRecorder()
	router.ServeHTTP(rrEnc, reqEnc)
	if rrEnc.Code != http.StatusOK {
		t.Fatalf("échec /encrypt mock strict: %d - %s", rrEnc.Code, rrEnc.Body.String())
	}

	var encResp EncryptResponse
	if err := json.NewDecoder(rrEnc.Body).Decode(&encResp); err != nil {
		t.Fatal(err)
	}
	if encResp.SuiteID != uint16(crypto.SuiteMock) {
		t.Fatalf("SuiteID attendu 0x%04X, obtenu 0x%04X", uint16(crypto.SuiteMock), encResp.SuiteID)
	}

	// Déchiffrement avec vérification stricte
	decBody, _ := json.Marshal(DecryptRequest{
		EnvelopeMeta:    encResp.EnvelopeMeta,
		EncapsulatedKey: encResp.EncapsulatedKey,
		Nonce:           encResp.Nonce,
		Ciphertext:      encResp.Ciphertext,
	})
	reqDec := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(decBody))
	reqDec.Header.Set("Content-Type", "application/json")
	rrDec := httptest.NewRecorder()
	router.ServeHTTP(rrDec, reqDec)
	if rrDec.Code != http.StatusOK {
		t.Fatalf("échec /decrypt mock strict (régression): %d - %s", rrDec.Code, rrDec.Body.String())
	}

	var decResp DecryptResponse
	_ = json.NewDecoder(rrDec.Body).Decode(&decResp)
	if decResp.Plaintext != string(testMsg) {
		t.Fatalf("incohérence mock decrypt: %q != %q", decResp.Plaintext, string(testMsg))
	}
}

func TestAPI_MockMode(t *testing.T) {
	router := api.NewRouter(&config.Config{Port: 8080, MaxPayloadBytes: 1 << 20}, crypto.NewMockEngine())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	var resp api.HealthResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.MockMode {
		t.Fatal("MockMode doit être true")
	}
}

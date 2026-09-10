package tests

import (
	"bytes"
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

func setupTestServer(t *testing.T, mockMode bool) (http.Handler, crypto.Engine) {
	cfg := &config.Config{
		Port:            8080,
		MockMode:        mockMode,
		MaxPayloadBytes: 10 * 1024 * 1024,
	}

	var engine crypto.Engine
	var err error
	if mockMode {
		engine = crypto.NewMockEngine()
	} else {
		engine, err = newMLKEMEngine()
		if err != nil {
			t.Fatalf("setup test server error: %v", err)
		}
	}

	router := api.NewRouter(cfg, engine)
	return router, engine
}

func TestAPI_HealthCheck(t *testing.T) {
	router, _ := setupTestServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code statut inattendu: obtenu %d, attendu %d", rr.Code, http.StatusOK)
	}

	var resp api.HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("erreur décodage json health: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("statut inattendu: %s", resp.Status)
	}
	if resp.MockMode != false {
		t.Errorf("MockMode inattendu: %t", resp.MockMode)
	}
	if resp.Algorithm != "ML-KEM-768+AES-256-GCM" {
		t.Errorf("algorithme inattendu: %s", resp.Algorithm)
	}
}

func TestAPI_GetPublicKey(t *testing.T) {
	router, _ := setupTestServer(t, false)

	req := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code statut inattendu: %d", rr.Code)
	}

	var resp api.PublicKeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("erreur décodage json public-key: %v", err)
	}

	if resp.PublicKey == "" {
		t.Fatal("la clé publique est vide")
	}

	rawPK, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		t.Fatalf("clé publique non encodée en base64 valide: %v", err)
	}

	if len(rawPK) != 1184 {
		t.Errorf("taille de clé publique ML-KEM-768 invalide: %d (attendu 1184)", len(rawPK))
	}
}

func TestAPI_GetPublicKey_ContentNegotiation(t *testing.T) {
	router, _ := setupTestServer(t, false)

	// 1. Accept avec q=0 ne doit PAS déclencher le binaire (doit retourner du JSON)
	reqQ0 := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	reqQ0.Header.Set("Accept", "application/octet-stream;q=0, application/json")
	rrQ0 := httptest.NewRecorder()
	router.ServeHTTP(rrQ0, reqQ0)
	if rrQ0.Code != http.StatusOK {
		t.Fatalf("statut inattendu pour q=0: %d", rrQ0.Code)
	}
	if ct := rrQ0.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("attendu application/json pour q=0, obtenu: %s", ct)
	}

	// 2. Accept octet-stream explicite doit retourner les octets bruts
	reqBin := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	reqBin.Header.Set("Accept", "application/octet-stream")
	rrBin := httptest.NewRecorder()
	router.ServeHTTP(rrBin, reqBin)
	if rrBin.Code != http.StatusOK {
		t.Fatalf("statut inattendu pour binaire: %d", rrBin.Code)
	}
	if ct := rrBin.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("attendu application/octet-stream, obtenu: %s", ct)
	}
	if len(rrBin.Body.Bytes()) != 1184 {
		t.Fatalf("taille binaire brute invalide: %d (attendu 1184)", len(rrBin.Body.Bytes()))
	}

	// 3. Accept avec q>0 doit accepter le format binaire
	reqQPos := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	reqQPos.Header.Set("Accept", "text/plain, application/octet-stream;q=0.8")
	rrQPos := httptest.NewRecorder()
	router.ServeHTTP(rrQPos, reqQPos)
	if rrQPos.Code != http.StatusOK {
		t.Fatalf("statut inattendu pour q>0: %d", rrQPos.Code)
	}
	if ct := rrQPos.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("attendu application/octet-stream pour q=0.8, obtenu: %s", ct)
	}
}

func TestAPI_EncryptDecryptFlow_Plaintext(t *testing.T) {
	router, _ := setupTestServer(t, false)

	secretText := "Message confidentiel d'entreprise sécurisé post-quantique"

	// 1. Chiffrement
	encryptReqBody, _ := json.Marshal(api.EncryptRequest{
		Plaintext: secretText,
	})

	req := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(encryptReqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("échec POST /encrypt: code %d, body: %s", rr.Code, rr.Body.String())
	}

	var encResp api.EncryptResponse
	if err := json.NewDecoder(rr.Body).Decode(&encResp); err != nil {
		t.Fatalf("erreur json encrypt: %v", err)
	}

	if encResp.EncapsulatedKey == "" || encResp.Ciphertext == "" || encResp.Nonce == "" {
		t.Fatal("champs de réponse de chiffrement incomplets")
	}

	// 2. Déchiffrement
	decryptReqBody, _ := json.Marshal(api.DecryptRequest{
		EnvelopeMeta: api.EnvelopeMeta{
			Algorithm: encResp.Algorithm,
			Version:   encResp.Version,
			SuiteID:   encResp.SuiteID,
		},
		EncapsulatedKey: encResp.EncapsulatedKey,
		Nonce:           encResp.Nonce,
		Ciphertext:      encResp.Ciphertext,
	})

	reqDec := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(decryptReqBody))
	reqDec.Header.Set("Content-Type", "application/json")
	rrDec := httptest.NewRecorder()

	router.ServeHTTP(rrDec, reqDec)

	if rrDec.Code != http.StatusOK {
		t.Fatalf("échec POST /decrypt: code %d, body: %s", rrDec.Code, rrDec.Body.String())
	}

	var decResp api.DecryptResponse
	if err := json.NewDecoder(rrDec.Body).Decode(&decResp); err != nil {
		t.Fatalf("erreur json decrypt: %v", err)
	}

	if decResp.Plaintext != secretText {
		t.Fatalf("texte déchiffré incorrect: '%s' != '%s'", decResp.Plaintext, secretText)
	}
}

func TestAPI_EncryptDecryptFlow_BinaryData(t *testing.T) {
	router, _ := setupTestServer(t, false)

	rawBinary := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x13, 0x37}
	base64Data := base64.StdEncoding.EncodeToString(rawBinary)

	// 1. Chiffrement
	encryptReqBody, _ := json.Marshal(api.EncryptRequest{
		Data: base64Data,
	})

	req := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(encryptReqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /encrypt data error: %d", rr.Code)
	}

	var encResp api.EncryptResponse
	_ = json.NewDecoder(rr.Body).Decode(&encResp)

	// 2. Déchiffrement
	decryptReqBody, _ := json.Marshal(api.DecryptRequest{
		EnvelopeMeta: api.EnvelopeMeta{
			Algorithm: encResp.Algorithm,
			Version:   encResp.Version,
			SuiteID:   encResp.SuiteID,
		},
		EncapsulatedKey: encResp.EncapsulatedKey,
		Nonce:           encResp.Nonce,
		Ciphertext:      encResp.Ciphertext,
	})

	reqDec := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(decryptReqBody))
	reqDec.Header.Set("Content-Type", "application/json")
	rrDec := httptest.NewRecorder()

	router.ServeHTTP(rrDec, reqDec)

	if rrDec.Code != http.StatusOK {
		t.Fatalf("POST /decrypt data error: %d", rrDec.Code)
	}

	var decResp api.DecryptResponse
	_ = json.NewDecoder(rrDec.Body).Decode(&decResp)

	if decResp.Data != base64Data {
		t.Fatalf("données binaires déchiffrées incorrectes: %s != %s", decResp.Data, base64Data)
	}
}

func TestAPI_DecryptCorrupted_Returns422(t *testing.T) {
	router, _ := setupTestServer(t, false)

	// Mauvaise clé ou altération
	corruptedReqBody, _ := json.Marshal(api.DecryptRequest{
		EnvelopeMeta: api.EnvelopeMeta{
			Algorithm: "ML-KEM-768+AES-256-GCM",
			Version:   crypto.ProtocolVersion,
			SuiteID:   uint16(crypto.SuiteMLKEM768_AES256GCM),
		},
		EncapsulatedKey: base64.StdEncoding.EncodeToString(make([]byte, 1088)),
		Nonce:           base64.StdEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:      base64.StdEncoding.EncodeToString([]byte("corrupted_payload")),
	})

	req := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(corruptedReqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code statut attendu 422 Unprocessable Entity, obtenu %d", rr.Code)
	}
}

func TestAPI_InvalidJSON_Returns400(t *testing.T) {
	router, _ := setupTestServer(t, false)

	req := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader([]byte("{invalid-json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code statut attendu 400 Bad Request, obtenu %d", rr.Code)
	}
}

func TestAPI_MockMode(t *testing.T) {
	router, _ := setupTestServer(t, true)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	var resp api.HealthResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.MockMode {
		t.Fatal("MockMode doit être true")
	}
}

func TestAPI_BinaryFastPath_Roundtrip(t *testing.T) {
	router, _ := setupTestServer(t, false)

	rawSecretPayload := []byte("Charge utile binaire ultra-rapide sans surcoût JSON !")

	// 1. Chiffrement binaire
	req := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(rawSecretPayload))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("échec chiffrement binaire: %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("Content-Type inattendu: %s", rr.Header().Get("Content-Type"))
	}

	encryptedBinary := rr.Body.Bytes()

	// 2. Déchiffrement binaire
	reqDec := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(encryptedBinary))
	reqDec.Header.Set("Content-Type", "application/octet-stream")
	rrDec := httptest.NewRecorder()

	router.ServeHTTP(rrDec, reqDec)

	if rrDec.Code != http.StatusOK {
		t.Fatalf("échec déchiffrement binaire: %d %s", rrDec.Code, rrDec.Body.String())
	}

	decryptedBinary := rrDec.Body.Bytes()

	if !bytes.Equal(rawSecretPayload, decryptedBinary) {
		t.Fatalf("incohérence des données binaires déchiffrées")
	}
}

func TestAPI_HealthCheck_MethodNotAllowed(t *testing.T) {
	router, _ := setupTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed || !strings.Contains(rr.Body.String(), "seuls GET et HEAD sont supportés") {
		t.Fatalf("réponse 405 invalide: %d - %s", rr.Code, rr.Body.String())
	}
}

func TestAPI_GenerateDataKey_BoundsValidation(t *testing.T) {
	router, _ := setupTestServer(t, false)
	for _, tc := range []struct {
		len  int
		want int
	}{
		{8, http.StatusBadRequest},
		{256, http.StatusBadRequest},
		{32, http.StatusOK},
	} {
		body, _ := json.Marshal(api.GenerateDataKeyRequest{KeyLength: tc.len})
		req := httptest.NewRequest(http.MethodPost, "/generate-key", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("longueur %d: statut attendu %d, obtenu %d", tc.len, tc.want, rr.Code)
		}
	}
}

func TestAPI_KEMDecapsulate_CorruptedKey_Returns422(t *testing.T) {
	router, _ := setupTestServer(t, false)
	body, _ := json.Marshal(api.DecapsulateRequest{EncapsulatedKey: base64.StdEncoding.EncodeToString([]byte("short"))})
	req := httptest.NewRequest(http.MethodPost, "/kem/decapsulate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("attendu 422, obtenu %d", rr.Code)
	}
}

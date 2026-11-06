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

func TestEnvelope_WrapAndUnwrapKey(t *testing.T) {
	router, _ := setupTestServer(t)

	// Clé cliente de 32 octets (AES-256)
	clientKey := make([]byte, 32)
	if _, err := rand.Read(clientKey); err != nil {
		t.Fatalf("erreur génération clé: %v", err)
	}
	defer crypto.Zeroize(clientKey)

	clientKeyB64 := base64.StdEncoding.EncodeToString(clientKey)

	// 1. POST /wrap-key
	wrapBody, _ := json.Marshal(WrapKeyRequest{
		PlaintextKey: clientKeyB64,
	})

	req := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(wrapBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("wrap-key a échoué avec statut %d: %s", rr.Code, rr.Body.String())
	}

	var wrapResp WrapKeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&wrapResp); err != nil {
		t.Fatalf("erreur décodage wrap response: %v", err)
	}

	if wrapResp.EncapsulatedKey == "" || wrapResp.Nonce == "" || wrapResp.WrappedKey == "" {
		t.Fatal("réponse wrap-key incomplète")
	}

	// 2. POST /unwrap-key
	unwrapBody, _ := json.Marshal(UnwrapKeyRequest{
		EnvelopeMeta: EnvelopeMeta{
			Algorithm: wrapResp.Algorithm,
			Version:   wrapResp.Version,
			SuiteID:   wrapResp.SuiteID,
		},
		EncapsulatedKey: wrapResp.EncapsulatedKey,
		Nonce:           wrapResp.Nonce,
		WrappedKey:      wrapResp.WrappedKey,
	})

	reqUnwrap := httptest.NewRequest(http.MethodPost, "/unwrap-key", bytes.NewReader(unwrapBody))
	reqUnwrap.Header.Set("Content-Type", "application/json")
	rrUnwrap := httptest.NewRecorder()

	router.ServeHTTP(rrUnwrap, reqUnwrap)

	if rrUnwrap.Code != http.StatusOK {
		t.Fatalf("unwrap-key a échoué avec statut %d: %s", rrUnwrap.Code, rrUnwrap.Body.String())
	}

	var unwrapResp UnwrapKeyResponse
	if err := json.NewDecoder(rrUnwrap.Body).Decode(&unwrapResp); err != nil {
		t.Fatalf("erreur décodage unwrap response: %v", err)
	}

	if unwrapResp.PlaintextKey != clientKeyB64 {
		t.Errorf("clé restituée différente ! attendu %s, obtenu %s", clientKeyB64, unwrapResp.PlaintextKey)
	}
	if unwrapResp.KeyLength != 32 {
		t.Errorf("taille de clé attendue 32, obtenu %d", unwrapResp.KeyLength)
	}
}

func TestEnvelope_GenerateDataKey(t *testing.T) {
	router, _ := setupTestServer(t)

	// 1. POST /generate-key (défaut 32 octets)
	req := httptest.NewRequest(http.MethodPost, "/generate-key", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("generate-key a échoué avec statut %d: %s", rr.Code, rr.Body.String())
	}

	var genResp GenerateDataKeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&genResp); err != nil {
		t.Fatalf("erreur décodage generate response: %v", err)
	}

	if genResp.PlaintextKey == "" || genResp.WrappedKey == "" || genResp.EncapsulatedKey == "" || genResp.Nonce == "" {
		t.Fatal("champs manquants dans la réponse generate-key")
	}

	rawKey, err := base64.StdEncoding.DecodeString(genResp.PlaintextKey)
	if err != nil || len(rawKey) != 32 {
		t.Fatalf("clé générée invalide (longueur %d, err %v)", len(rawKey), err)
	}
	defer crypto.Zeroize(rawKey)

	// 2. Déchiffrement de la clé enveloppée via /unwrap-key
	unwrapBody, _ := json.Marshal(UnwrapKeyRequest{
		EnvelopeMeta: EnvelopeMeta{
			Algorithm: genResp.Algorithm,
			Version:   genResp.Version,
			SuiteID:   genResp.SuiteID,
		},
		EncapsulatedKey: genResp.EncapsulatedKey,
		Nonce:           genResp.Nonce,
		WrappedKey:      genResp.WrappedKey,
	})

	reqUnwrap := httptest.NewRequest(http.MethodPost, "/unwrap-key", bytes.NewReader(unwrapBody))
	reqUnwrap.Header.Set("Content-Type", "application/json")
	rrUnwrap := httptest.NewRecorder()

	router.ServeHTTP(rrUnwrap, reqUnwrap)

	if rrUnwrap.Code != http.StatusOK {
		t.Fatalf("unwrap-key de la clé générée a échoué: %d", rrUnwrap.Code)
	}

	var unwrapResp UnwrapKeyResponse
	if err := json.NewDecoder(rrUnwrap.Body).Decode(&unwrapResp); err != nil {
		t.Fatalf("erreur décodage unwrap: %v", err)
	}

	if unwrapResp.PlaintextKey != genResp.PlaintextKey {
		t.Errorf("mismatch entre clé générée (%s) et clé unwrappée (%s)", genResp.PlaintextKey, unwrapResp.PlaintextKey)
	}
}

func TestEnvelope_PureKEM_EncapsulateDecapsulate(t *testing.T) {
	router, _ := setupTestServer(t)

	// 1. POST /kem/encapsulate
	req := httptest.NewRequest(http.MethodPost, "/kem/encapsulate", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("kem/encapsulate a échoué: %d %s", rr.Code, rr.Body.String())
	}

	var encapResp EncapsulateResponse
	if err := json.NewDecoder(rr.Body).Decode(&encapResp); err != nil {
		t.Fatalf("erreur décodage encapsulate response: %v", err)
	}

	if encapResp.EncapsulatedKey == "" || encapResp.SharedSecret == "" {
		t.Fatal("réponse encapsulate incomplète")
	}

	// 2. POST /kem/decapsulate
	decapBody, _ := json.Marshal(DecapsulateRequest{
		EncapsulatedKey: encapResp.EncapsulatedKey,
	})

	reqDecap := httptest.NewRequest(http.MethodPost, "/kem/decapsulate", bytes.NewReader(decapBody))
	reqDecap.Header.Set("Content-Type", "application/json")
	rrDecap := httptest.NewRecorder()

	router.ServeHTTP(rrDecap, reqDecap)

	if rrDecap.Code != http.StatusOK {
		t.Fatalf("kem/decapsulate a échoué: %d %s", rrDecap.Code, rrDecap.Body.String())
	}

	var decapResp DecapsulateResponse
	if err := json.NewDecoder(rrDecap.Body).Decode(&decapResp); err != nil {
		t.Fatalf("erreur décodage decapsulate response: %v", err)
	}

	if decapResp.SharedSecret != encapResp.SharedSecret {
		t.Errorf("secret partagé décapsulé différent ! attendu %s, obtenu %s", encapResp.SharedSecret, decapResp.SharedSecret)
	}
	if encapResp.Algorithm != "ML-KEM-768" {
		t.Errorf("algorithme encapsulate inattendu: attendu ML-KEM-768, obtenu %s", encapResp.Algorithm)
	}
	if decapResp.Algorithm != encapResp.Algorithm {
		t.Errorf("incohérence métadonnées KEM : encapsulate=%s, decapsulate=%s", encapResp.Algorithm, decapResp.Algorithm)
	}
}

func TestEnvelope_BinaryFastPath(t *testing.T) {
	router, _ := setupTestServer(t)

	clientKey := make([]byte, 32)
	for i := range clientKey {
		clientKey[i] = byte(i + 1)
	}
	defer crypto.Zeroize(clientKey)

	// 1. Binary Wrap
	req := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(clientKey))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("binary wrap-key a échoué: %d", rr.Code)
	}

	wrappedBinary := rr.Body.Bytes()
	if len(wrappedBinary) < 2+12+16 {
		t.Fatalf("payload binaire trop court: %d", len(wrappedBinary))
	}

	// 2. Binary Unwrap
	reqUnwrap := httptest.NewRequest(http.MethodPost, "/unwrap-key", bytes.NewReader(wrappedBinary))
	reqUnwrap.Header.Set("Content-Type", "application/octet-stream")
	rrUnwrap := httptest.NewRecorder()

	router.ServeHTTP(rrUnwrap, reqUnwrap)

	if rrUnwrap.Code != http.StatusOK {
		t.Fatalf("binary unwrap-key a échoué: %d", rrUnwrap.Code)
	}

	recoveredKey := rrUnwrap.Body.Bytes()
	if !bytes.Equal(recoveredKey, clientKey) {
		t.Fatalf("clé binaire unwrappée corrompue")
	}
}

func TestEnvelope_TamperedWrappedKey(t *testing.T) {
	router, _ := setupTestServer(t)

	clientKey := make([]byte, 32)
	clientKeyB64 := base64.StdEncoding.EncodeToString(clientKey)

	wrapBody, _ := json.Marshal(WrapKeyRequest{
		PlaintextKey: clientKeyB64,
	})

	req := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(wrapBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var wrapResp WrapKeyResponse
	_ = json.NewDecoder(rr.Body).Decode(&wrapResp)

	// Altération du wrapped_key
	rawWrapped, _ := base64.StdEncoding.DecodeString(wrapResp.WrappedKey)
	rawWrapped[0] ^= 0xFF // corruption de bit
	tamperedWrappedKey := base64.StdEncoding.EncodeToString(rawWrapped)

	unwrapBody, _ := json.Marshal(UnwrapKeyRequest{
		EnvelopeMeta: EnvelopeMeta{
			Algorithm: wrapResp.Algorithm,
			Version:   wrapResp.Version,
			SuiteID:   wrapResp.SuiteID,
		},
		EncapsulatedKey: wrapResp.EncapsulatedKey,
		Nonce:           wrapResp.Nonce,
		WrappedKey:      tamperedWrappedKey,
	})

	reqUnwrap := httptest.NewRequest(http.MethodPost, "/unwrap-key", bytes.NewReader(unwrapBody))
	reqUnwrap.Header.Set("Content-Type", "application/json")
	rrUnwrap := httptest.NewRecorder()
	router.ServeHTTP(rrUnwrap, reqUnwrap)

	if rrUnwrap.Code != http.StatusUnprocessableEntity {
		t.Errorf("le déchiffrement d'une clé altérée aurait dû retourner 422, obtenu %d", rrUnwrap.Code)
	}
}

// TestEnvelope_HeaderlessBinaryRejected vérifie que seul le format binaire avec en-tête 'PQ' est accepté.
func TestEnvelope_HeaderlessBinaryRejected(t *testing.T) {
	cfgStrict := &config.Config{
		Port:            8080,
		MaxPayloadBytes: 10 * 1024 * 1024,
	}
	engineStrict, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}
	routerStrict := api.NewRouter(cfgStrict, engineStrict)

	// Chiffrement binaire V2 standard
	msg := []byte("Message pour test legacy vs v2")
	reqEnc := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(msg))
	reqEnc.Header.Set("Content-Type", "application/octet-stream")
	rrEnc := httptest.NewRecorder()
	routerStrict.ServeHTTP(rrEnc, reqEnc)
	if rrEnc.Code != http.StatusOK {
		t.Fatalf("échec chiffrement binaire: %d", rrEnc.Code)
	}
	v2BinaryEnvelope := rrEnc.Body.Bytes()

	// Forge d'une enveloppe binaire historique legacy [keyLen(2B) + encapKey + nonce(12B) + cipher] sans 'PQ'
	// V2 format: 'P' 'Q' 0x02 suiteID(2B) keyLen(2B)...
	legacyBinaryEnvelope := v2BinaryEnvelope[5:] // tronque Magic(2B) + Version(1B) + SuiteID(2B)

	// A. Le serveur strict DOIT rejeter l'enveloppe binaire legacy
	reqDecLegacy := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(legacyBinaryEnvelope))
	reqDecLegacy.Header.Set("Content-Type", "application/octet-stream")
	rrDecLegacy := httptest.NewRecorder()
	routerStrict.ServeHTTP(rrDecLegacy, reqDecLegacy)
	if rrDecLegacy.Code != http.StatusBadRequest {
		t.Errorf("le serveur strict aurait dû rejeter l'enveloppe binaire legacy, statut: %d", rrDecLegacy.Code)
	}

	// B. Le serveur strict ACCEPTE l'enveloppe binaire V2
	reqDecV2 := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(v2BinaryEnvelope))
	reqDecV2.Header.Set("Content-Type", "application/octet-stream")
	rrDecV2 := httptest.NewRecorder()
	routerStrict.ServeHTTP(rrDecV2, reqDecV2)
	if rrDecV2.Code != http.StatusOK {
		t.Errorf("le serveur strict a rejeté l'enveloppe binaire V2 légitime: %d", rrDecV2.Code)
	}

}

// TestEnvelope_BinarySuiteIDMismatch vérifie le rejet immédiat d'une enveloppe avec un suite_id discordant.
func TestEnvelope_BinarySuiteIDMismatch(t *testing.T) {
	cfg := &config.Config{
		Port:            8080,
		MaxPayloadBytes: 10 * 1024 * 1024,
	}
	// Serveur ML-KEM-768 (suite_id = 0x0001)
	engine768, _ := newMLKEMEngine()
	router768 := api.NewRouter(cfg, engine768)

	// Client ML-KEM-1024 (suite_id = 0x0002)
	engine1024, _ := newMLKEM1024Engine()
	router1024 := api.NewRouter(cfg, engine1024)

	// Chiffrement sous ML-KEM-1024
	reqEnc := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader([]byte("Test suite mismatch")))
	reqEnc.Header.Set("Content-Type", "application/octet-stream")
	rrEnc := httptest.NewRecorder()
	router1024.ServeHTTP(rrEnc, reqEnc)
	if rrEnc.Code != http.StatusOK {
		t.Fatalf("échec chiffrement 1024: %d", rrEnc.Code)
	}
	envelope1024 := rrEnc.Body.Bytes()

	// Tentative de déchiffrement sur le serveur 768
	reqDec := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(envelope1024))
	reqDec.Header.Set("Content-Type", "application/octet-stream")
	rrDec := httptest.NewRecorder()
	router768.ServeHTTP(rrDec, reqDec)

	if rrDec.Code != http.StatusBadRequest {
		t.Fatalf("attendu 400 Bad Request pour suite_id discordant, obtenu %d: %s", rrDec.Code, rrDec.Body.String())
	}
}

func TestEnvelope_BinaryWrapKey_LengthBounds(t *testing.T) {
	router, _ := setupTestServer(t)

	// Cas 1 : Clé trop courte (< 16 octets)
	shortKey := make([]byte, 10)
	reqShort := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(shortKey))
	reqShort.Header.Set("Content-Type", "application/octet-stream")
	rrShort := httptest.NewRecorder()
	router.ServeHTTP(rrShort, reqShort)
	if rrShort.Code != http.StatusBadRequest {
		t.Errorf("attendu 400 pour clé binaire de 10 octets, obtenu %d", rrShort.Code)
	}

	// Cas 2 : Clé trop longue (> 128 octets) - Régression P1 audit NSA
	longKey := make([]byte, 256)
	reqLong := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(longKey))
	reqLong.Header.Set("Content-Type", "application/octet-stream")
	rrLong := httptest.NewRecorder()
	router.ServeHTTP(rrLong, reqLong)
	if rrLong.Code != http.StatusBadRequest {
		t.Errorf("attendu 400 pour clé binaire de 256 octets, obtenu %d", rrLong.Code)
	}

	// Cas 3 : Clé valide (32 octets = AES-256)
	validKey := make([]byte, 32)
	reqValid := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(validKey))
	reqValid.Header.Set("Content-Type", "application/octet-stream")
	rrValid := httptest.NewRecorder()
	router.ServeHTTP(rrValid, reqValid)
	if rrValid.Code != http.StatusOK {
		t.Errorf("attendu 200 pour clé binaire valide de 32 octets, obtenu %d: %s", rrValid.Code, rrValid.Body.String())
	}
}

func TestEnvelope_NodeAndPhpClientPayloadCompatibility(t *testing.T) {
	router, _ := setupTestServer(t)

	dek := []byte("01234567890123456789012345678901") // 32 bytes
	wrapPayload, _ := json.Marshal(map[string]string{
		"plaintext_key": base64.StdEncoding.EncodeToString(dek),
	})
	req := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(wrapPayload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("échec wrapKey format client Node/PHP: %d - %s", rr.Code, rr.Body.String())
	}

	var wrapResp map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&wrapResp)

	// Unwrap
	unwrapPayload, _ := json.Marshal(wrapResp)
	reqUnwrap := httptest.NewRequest(http.MethodPost, "/unwrap-key", bytes.NewReader(unwrapPayload))
	reqUnwrap.Header.Set("Content-Type", "application/json")
	rrUnwrap := httptest.NewRecorder()
	router.ServeHTTP(rrUnwrap, reqUnwrap)

	if rrUnwrap.Code != http.StatusOK {
		t.Fatalf("échec unwrapKey format client: %d - %s", rrUnwrap.Code, rrUnwrap.Body.String())
	}

	var unwrapResp UnwrapKeyResponse
	_ = json.NewDecoder(rrUnwrap.Body).Decode(&unwrapResp)
	unwrappedKey, _ := base64.StdEncoding.DecodeString(unwrapResp.PlaintextKey)
	if !bytes.Equal(unwrappedKey, dek) {
		t.Fatalf("clé restituée différente de la clé injectée")
	}
}

func TestEnvelope_PayloadTooLargeReturns413(t *testing.T) {
	cfg := &config.Config{
		Port:            8080,
		MaxPayloadBytes: 100, // Petite limite de 100 octets
	}
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(cfg, engine)

	// 1. Dépassement binaire -> HTTP 413
	largeBinary := make([]byte, 200)
	reqBin := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(largeBinary))
	reqBin.Header.Set("Content-Type", "application/octet-stream")
	rrBin := httptest.NewRecorder()
	router.ServeHTTP(rrBin, reqBin)
	if rrBin.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("attendu HTTP 413 pour dépassement binaire, obtenu: %d", rrBin.Code)
	}

	// 2. Dépassement JSON -> HTTP 413
	largeJSON := []byte(`{"plaintext":"` + strings.Repeat("A", 200) + `"}`)
	reqJSON := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(largeJSON))
	reqJSON.Header.Set("Content-Type", "application/json")
	rrJSON := httptest.NewRecorder()
	router.ServeHTTP(rrJSON, reqJSON)
	if rrJSON.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("attendu HTTP 413 pour dépassement JSON, obtenu: %d", rrJSON.Code)
	}
}

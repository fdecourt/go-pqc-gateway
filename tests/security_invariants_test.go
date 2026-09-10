package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

// TestSecurity_CrossContextRefusal vérifie que la séparation des domaines interdit la confusion d'usage :
// Un chiffré généré pour l'enveloppement de clé (KEY_WRAPPING) NE DOIT PAS pouvoir être déchiffré
// comme des données applicatives (DATA_ENCRYPTION), et vice versa.
func TestSecurity_CrossContextRefusal(t *testing.T) {
	ctx := context.Background()
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("échec d'initialisation: %v", err)
	}

	dek := []byte("01234567890123456789012345678901") // 32 octets

	// 1. Enveloppement de la clé (Usage: KEY_WRAPPING_DEK)
	wrapped, err := crypto.WrapKey(ctx, engine, dek, nil)
	if err != nil {
		t.Fatalf("échec WrapKey: %v", err)
	}

	// 2. Tentative frauduleuse de déchiffrement via le canal de données (Usage: DATA_ENCRYPTION)
	crossPayload := &crypto.SealedPayload{
		Algorithm:       wrapped.Algorithm,
		Version:         wrapped.Version,
		SuiteID:         wrapped.SuiteID,
		EncapsulatedKey: wrapped.EncapsulatedKey,
		Nonce:           wrapped.Nonce,
		Data:            wrapped.Data,
	}

	_, err = crypto.Decrypt(ctx, engine, crossPayload)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: le déchiffrement DATA_ENCRYPTION a accepté un chiffré KEY_WRAPPING_DEK !")
	}
	if !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("attendu crypto.ErrDecryptionFailed pour usage divergent, obtenu: %v", err)
	}

	// 3. Réciproque : Chiffrement de données applicatives (Usage: DATA_ENCRYPTION)
	dataPayload, err := crypto.Encrypt(ctx, engine, dek, nil)
	if err != nil {
		t.Fatalf("échec Encrypt: %v", err)
	}

	// Tentative frauduleuse d'unwrapping de données applicatives (Usage: KEY_WRAPPING_DEK)
	_, err = crypto.UnwrapKey(ctx, engine, dataPayload.EncapsulatedKey, dataPayload.Nonce, dataPayload.Data)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: UnwrapKey a accepté un chiffré DATA_ENCRYPTION !")
	}
	if !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("attendu crypto.ErrDecryptionFailed pour usage divergent sur UnwrapKey, obtenu: %v", err)
	}

	// 4. Invariant de vivacité : UnwrapKey sur l'enveloppe légitime doit réussir
	unwrapped, err := crypto.UnwrapKey(ctx, engine, wrapped.EncapsulatedKey, wrapped.Nonce, wrapped.Data)
	if err != nil {
		t.Fatalf("échec UnwrapKey légitime: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("clé unwrapped non conforme au DEK initial")
	}
}

// TestSecurity_CrossAlgorithmRefusal vérifie qu'un chiffré ML-KEM-768 ne peut pas être déchiffré par ML-KEM-1024.
func TestSecurity_CrossAlgorithmRefusal(t *testing.T) {
	ctx := context.Background()

	engine768, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("échec init 768: %v", err)
	}

	engine1024, err := newMLKEM1024Engine()
	if err != nil {
		t.Fatalf("échec init 1024: %v", err)
	}

	plaintext := []byte("Message top-secret pour validation d'isolation d'algorithme")
	payload768, err := crypto.Encrypt(ctx, engine768, plaintext, nil)
	if err != nil {
		t.Fatalf("échec chiffrement 768: %v", err)
	}

	// Tentative de déchiffrement par le moteur 1024
	_, err = crypto.Decrypt(ctx, engine1024, payload768)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: Le moteur ML-KEM-1024 a déchiffré un payload ML-KEM-768 !")
	}
}

// TestSecurity_MismatchedKeyImport_MLKEM768 vérifie le rejet de paires dissociées (Alice PK + Bob SK).
func TestSecurity_MismatchedKeyImport_MLKEM768(t *testing.T) {
	engine1, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}
	exporter1 := engine1.(crypto.KeyExporter)
	pk1, _, _ := exporter1.ExportKeys()

	engine2, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}
	exporter2 := engine2.(crypto.KeyExporter)
	_, sk2, _ := exporter2.ExportKeys()

	// Tentative d'importation incohérente : Clé publique d'Alice avec clé privée de Bob
	_, err = newMLKEM768WithKeys(pk1, sk2)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: newMLKEM768WithKeys a accepté une paire de clés dissociée !")
	}
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Errorf("erreur attendue ErrInvalidKey, obtenu: %v", err)
	}

	// Test de résistance au crash sur clé tronquée
	_, err = newMLKEM768WithKeys(pk1[:10], sk2)
	if err == nil {
		t.Fatal("clé publique tronquée non rejetée")
	}

	_, err = newMLKEM768WithKeys(pk1, sk2[:10])
	if err == nil {
		t.Fatal("clé privée tronquée non rejetée")
	}
}

// TestSecurity_MismatchedKeyImport_DualHybrid vérifie le contrôle de cohérence croisée pour X25519 et ML-KEM.
func TestSecurity_MismatchedKeyImport_DualHybrid(t *testing.T) {
	dual1, err := newDualHybridEngine()
	if err != nil {
		t.Fatal(err)
	}
	exporter1 := dual1.(crypto.KeyExporter)
	pk1, _, _ := exporter1.ExportKeys()

	dual2, err := newDualHybridEngine()
	if err != nil {
		t.Fatal(err)
	}
	exporter2 := dual2.(crypto.KeyExporter)
	_, sk2, _ := exporter2.ExportKeys()

	// Tentative d'importation avec clés complètement dissociées
	_, err = newDualHybridEngineWithKeys(pk1, sk2)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: newDualHybridEngineWithKeys a accepté une paire Dual dissociée !")
	}
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Errorf("erreur attendue ErrInvalidKey, obtenu: %v", err)
	}

	// Clé tronquée (ne doit jamais paniquer sur slicing)
	_, err = newDualHybridEngineWithKeys([]byte("court"), []byte("court"))
	if err == nil {
		t.Fatal("clés courtes non rejetées")
	}
}

// TestSecurity_MLKEM1024_Category5 valide le fonctionnement complet de ML-KEM-1024 (NIST FIPS 203 Catégorie 5).
func TestSecurity_MLKEM1024_Category5(t *testing.T) {
	ctx := context.Background()
	engine, err := newMLKEM1024Engine()
	if err != nil {
		t.Fatalf("échec NewMLKEM1024Engine: %v", err)
	}

	pk := engine.GetPublicKey()
	// Taille standard ML-KEM-1024 NIST FIPS 203 = 1568 octets
	if len(pk) != 1568 {
		t.Fatalf("taille clé publique ML-KEM-1024 invalide: %d (attendu 1568)", len(pk))
	}

	msg := []byte("Document confidentiel protégé au niveau maximal NIST Catégorie 5")
	payload, err := crypto.Encrypt(ctx, engine, msg, nil)
	if err != nil {
		t.Fatalf("échec chiffrement 1024: %v", err)
	}

	// Taille du ciphertext ML-KEM-1024 = 1568 octets
	if len(payload.EncapsulatedKey) != 1568 {
		t.Fatalf("taille ciphertext ML-KEM-1024 invalide: %d (attendu 1568)", len(payload.EncapsulatedKey))
	}

	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("échec déchiffrement 1024: %v", err)
	}

	if string(decrypted) != string(msg) {
		t.Fatal("incohérence des données déchiffrées sous ML-KEM-1024")
	}
}

// TestSecurity_DualHybrid1024_Category5 valide le schéma Dual (X25519 + ML-KEM-1024) avec combinateur HKDF-SHA256 transcript-bound.
func TestSecurity_DualHybrid1024_Category5(t *testing.T) {
	ctx := context.Background()
	engine, err := newDualHybrid1024Engine()
	if err != nil {
		t.Fatalf("échec NewDualHybrid1024Engine: %v", err)
	}

	pk := engine.GetPublicKey()
	// X25519 (32) + ML-KEM-1024 (1568) = 1600 octets
	if len(pk) != 1600 {
		t.Fatalf("taille clé publique Dual 1024 invalide: %d (attendu 1600)", len(pk))
	}

	msg := []byte("Dual Hybrid X25519 + ML-KEM-1024 test message")
	payload, err := crypto.Encrypt(ctx, engine, msg, nil)
	if err != nil {
		t.Fatalf("échec chiffrement Dual 1024: %v", err)
	}

	// 32 (X25519 pub éphémère) + 1568 (ML-KEM-1024 ciphertext) = 1600 octets
	if len(payload.EncapsulatedKey) != 1600 {
		t.Fatalf("taille encapsulation Dual 1024 invalide: %d (attendu 1600)", len(payload.EncapsulatedKey))
	}

	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("échec déchiffrement Dual 1024: %v", err)
	}

	if string(decrypted) != string(msg) {
		t.Fatal("incohérence déchiffrement Dual 1024")
	}

	// Falsification bit-à-bit du ciphertext dual
	corrupted := &crypto.SealedPayload{
		Algorithm:       payload.Algorithm,
		EncapsulatedKey: append([]byte(nil), payload.EncapsulatedKey...),
		Nonce:           payload.Nonce,
		Data:            payload.Data,
	}
	corrupted.EncapsulatedKey[0] ^= 0xFF // Altère la partie X25519

	_, err = crypto.Decrypt(ctx, engine, corrupted)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: Altération de la composante X25519 non détectée par le combinateur !")
	}

	corrupted2 := &crypto.SealedPayload{
		Algorithm:       payload.Algorithm,
		EncapsulatedKey: append([]byte(nil), payload.EncapsulatedKey...),
		Nonce:           payload.Nonce,
		Data:            payload.Data,
	}
	corrupted2.EncapsulatedKey[100] ^= 0xFF // Altère la partie ML-KEM

	_, err = crypto.Decrypt(ctx, engine, corrupted2)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: Altération de la composante ML-KEM non détectée par le combinateur !")
	}
}

// TestSecurity_UnknownAlgorithmRejected vérifie qu'un algorithme non présent dans l'allowlist
// est immédiatement rejeté avec une erreur fatale ErrUnsupportedAlgorithm, et qu'un algo vide
// retombe proprement et sans ambiguïté sur ML-KEM-768.
func TestSecurity_UnknownAlgorithmRejected(t *testing.T) {
	ctx := context.Background()

	// Algorithmes invalides ou fautes de frappe
	invalidAlgos := []string{
		"ROT13",
		"ML-KEM-1025",
		"DUAL-HYBRID-XYZ",
		"AES-256-GCM",
		"RSA-4096",
		"ECDH-X25519",
	}

	for _, algo := range invalidAlgos {
		_, err := crypto.BuildEngine(ctx, crypto.EngineOptions{Algorithm: algo}, nil)
		if err == nil {
			t.Fatalf("SÉCURITÉ VIOLÉE: algorithme inconnu %q accepté par la factory !", algo)
		}
		if !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
			t.Errorf("erreur attendue ErrUnsupportedAlgorithm pour %q, obtenu: %v", algo, err)
		}
	}

	// Algorithme vide doit explicitement retomber sur le défaut ML-KEM-1024
	engine, err := crypto.BuildEngine(ctx, crypto.EngineOptions{Algorithm: ""}, nil)
	if err != nil {
		t.Fatalf("échec initialisation algo vide par défaut: %v", err)
	}
	if engine.Name() != "ML-KEM-1024+AES-256-GCM" {
		t.Errorf("moteur inattendu pour algo vide: %s (attendu ML-KEM-1024+AES-256-GCM)", engine.Name())
	}

	// Algorithmes supportés dans l'allowlist
	validAlgos := []string{
		"ML-KEM-768",
		"ML-KEM-1024",
		"DUAL-X25519+ML-KEM-768",
		"DUAL-HYBRID",
		"DUAL-X25519+ML-KEM-1024",
	}
	for _, algo := range validAlgos {
		eng, err := crypto.BuildEngine(ctx, crypto.EngineOptions{Algorithm: algo}, nil)
		if err != nil {
			t.Fatalf("échec initialisation algo valide %q: %v", algo, err)
		}
		if eng == nil {
			t.Fatalf("moteur nil pour algo valide %q", algo)
		}
	}
}

// TestSecurity_FalsifiedEnvelopeAlgorithmRefused vérifie qu'un payload annonçant un algorithme
// menteur (divergent du moteur local) est fermement rejeté avec HTTP 400 Bad Request.
func TestSecurity_FalsifiedEnvelopeAlgorithmRefused(t *testing.T) {
	router, engine := setupTestServer(t, false) // Serveur démarré avec ML-KEM-768

	// 1. Chiffrement légitime
	plainMsg := []byte("Message d'évaluation d'enveloppe cryptographique")
	encReq := api.EncryptRequest{
		Data: base64.StdEncoding.EncodeToString(plainMsg),
	}
	body, _ := json.Marshal(encReq)
	req := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("échec chiffrement: status %d", rr.Code)
	}

	var encResp api.EncryptResponse
	_ = json.NewDecoder(rr.Body).Decode(&encResp)

	// 2. Déchiffrement avec un champ algorithm falsifié (menteur)
	decReqFalsified := api.DecryptRequest{
		EnvelopeMeta: api.EnvelopeMeta{
			Algorithm: "ML-KEM-1024", // Falsification : prétend être du 1024
			Version:   encResp.Version,
			SuiteID:   encResp.SuiteID,
		},
		EncapsulatedKey: encResp.EncapsulatedKey,
		Nonce:           encResp.Nonce,
		Ciphertext:      encResp.Ciphertext,
	}
	falsifiedBody, _ := json.Marshal(decReqFalsified)
	req2 := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(falsifiedBody))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("SÉCURITÉ VIOLÉE: /decrypt a accepté un algorithm falsifié (statut %d, attendu 400)", rr2.Code)
	}

	// 3. Déchiffrement avec un autre algorithme falsifié (DUAL-X25519+ML-KEM-768)
	decReqFalsified2 := decReqFalsified
	decReqFalsified2.Algorithm = "DUAL-X25519+ML-KEM-768"
	falsifiedBody2, _ := json.Marshal(decReqFalsified2)
	req3 := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(falsifiedBody2))
	req3.Header.Set("Content-Type", "application/json")
	rr3 := httptest.NewRecorder()
	router.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusBadRequest {
		t.Fatalf("SÉCURITÉ VIOLÉE: /decrypt a accepté un algo dual falsifié (statut %d, attendu 400)", rr3.Code)
	}

	// 4. Déchiffrement avec suite_id falsifié
	decReqFalsifiedSuite := decReqFalsified
	decReqFalsifiedSuite.Algorithm = encResp.Algorithm
	decReqFalsifiedSuite.SuiteID = 0x9999
	falsifiedBodySuite, _ := json.Marshal(decReqFalsifiedSuite)
	reqSuite := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(falsifiedBodySuite))
	reqSuite.Header.Set("Content-Type", "application/json")
	rrSuite := httptest.NewRecorder()
	router.ServeHTTP(rrSuite, reqSuite)

	if rrSuite.Code != http.StatusBadRequest {
		t.Fatalf("SÉCURITÉ VIOLÉE: /decrypt a accepté un suite_id falsifié (statut %d, attendu 400)", rrSuite.Code)
	}

	// 5. Déchiffrement avec version falsifiée
	decReqFalsifiedVer := decReqFalsified
	decReqFalsifiedVer.Algorithm = encResp.Algorithm
	decReqFalsifiedVer.Version = "OBSOLETE-V0"
	falsifiedBodyVer, _ := json.Marshal(decReqFalsifiedVer)
	reqVer := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(falsifiedBodyVer))
	reqVer.Header.Set("Content-Type", "application/json")
	rrVer := httptest.NewRecorder()
	router.ServeHTTP(rrVer, reqVer)

	if rrVer.Code != http.StatusBadRequest {
		t.Fatalf("SÉCURITÉ VIOLÉE: /decrypt a accepté une version falsifiée (statut %d, attendu 400)", rrVer.Code)
	}

	// 6. Déchiffrement légitime avec req.Algorithm vide (optionnel mais Version et SuiteID valides)
	decReqEmpty := decReqFalsified
	decReqEmpty.Algorithm = ""
	emptyBody, _ := json.Marshal(decReqEmpty)
	req4 := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(emptyBody))
	req4.Header.Set("Content-Type", "application/json")
	rr4 := httptest.NewRecorder()
	router.ServeHTTP(rr4, req4)

	if rr4.Code != http.StatusOK {
		t.Fatalf("déchiffrement légitime algo vide échoué: statut %d", rr4.Code)
	}

	// 7. Déchiffrement légitime avec req.Algorithm canonique exact
	decReqValid := decReqFalsified
	decReqValid.Algorithm = encResp.Algorithm
	validBody, _ := json.Marshal(decReqValid)
	req5 := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(validBody))
	req5.Header.Set("Content-Type", "application/json")
	rr5 := httptest.NewRecorder()
	router.ServeHTTP(rr5, req5)

	if rr5.Code != http.StatusOK {
		t.Fatalf("déchiffrement légitime algo exact échoué: statut %d", rr5.Code)
	}

	// 7b. Rejet de l'alias non canonique ("ML-KEM-768") en mode strict (allowLegacy=false)
	decReqAlias := decReqFalsified
	decReqAlias.Algorithm = "ML-KEM-768"
	aliasBody, _ := json.Marshal(decReqAlias)
	reqAlias := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(aliasBody))
	reqAlias.Header.Set("Content-Type", "application/json")
	rrAlias := httptest.NewRecorder()
	router.ServeHTTP(rrAlias, reqAlias)

	if rrAlias.Code != http.StatusBadRequest {
		t.Fatalf("SÉCURITÉ VIOLÉE: /decrypt strict a accepté un alias non canonique (statut %d, attendu 400)", rrAlias.Code)
	}

	// 7c. Acceptation de l'alias non canonique ("ML-KEM-768") en mode permissif (allowLegacy=true)
	exporter := engine.(crypto.KeyExporter)
	pk, sk, _ := exporter.ExportKeys()
	permEngine, err := crypto.NewEngineWithKeysAndPolicy("ML-KEM-768", pk, sk, true)
	if err != nil {
		t.Fatal(err)
	}
	permRouter := api.NewRouter(&config.Config{
		AllowLegacyEnvelopes: true,
	}, permEngine)
	defer permRouter.Close()
	reqPerm := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewReader(aliasBody))
	reqPerm.Header.Set("Content-Type", "application/json")
	rrPerm := httptest.NewRecorder()
	permRouter.ServeHTTP(rrPerm, reqPerm)
	if rrPerm.Code != http.StatusOK {
		t.Fatalf("déchiffrement legacy avec alias KEM échoué: statut %d", rrPerm.Code)
	}

	// 8. Test sur /unwrap-key avec algo falsifié
	wrapReq := api.WrapKeyRequest{
		PlaintextKey: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
	}
	wrapBody, _ := json.Marshal(wrapReq)
	reqWrap := httptest.NewRequest(http.MethodPost, "/wrap-key", bytes.NewReader(wrapBody))
	reqWrap.Header.Set("Content-Type", "application/json")
	rrWrap := httptest.NewRecorder()
	router.ServeHTTP(rrWrap, reqWrap)

	if rrWrap.Code != http.StatusOK {
		t.Fatalf("échec wrap-key: statut %d", rrWrap.Code)
	}

	var wrapResp api.WrapKeyResponse
	_ = json.NewDecoder(rrWrap.Body).Decode(&wrapResp)

	unwrapFalsified := api.UnwrapKeyRequest{
		EnvelopeMeta: api.EnvelopeMeta{
			Algorithm: "ML-KEM-1024",
			Version:   wrapResp.Version,
			SuiteID:   wrapResp.SuiteID,
		},
		EncapsulatedKey: wrapResp.EncapsulatedKey,
		Nonce:           wrapResp.Nonce,
		WrappedKey:      wrapResp.WrappedKey,
	}
	unwrapBody, _ := json.Marshal(unwrapFalsified)
	reqUnwrap := httptest.NewRequest(http.MethodPost, "/unwrap-key", bytes.NewReader(unwrapBody))
	reqUnwrap.Header.Set("Content-Type", "application/json")
	rrUnwrap := httptest.NewRecorder()
	router.ServeHTTP(rrUnwrap, reqUnwrap)

	if rrUnwrap.Code != http.StatusBadRequest {
		t.Fatalf("SÉCURITÉ VIOLÉE: /unwrap-key a accepté un algo falsifié (statut %d, attendu 400)", rrUnwrap.Code)
	}
}

// TestSecurity_Dual768_ExternalPublicKey valide le chiffrement par un émetteur externe
// disposant uniquement de la clé publique composite d'Alice pour DUAL-X25519+ML-KEM-768.
func TestSecurity_Dual768_ExternalPublicKey(t *testing.T) {
	ctx := context.Background()

	// Alice génère son moteur Dual-768 et diffuse sa clé publique
	aliceEngine, err := newDualHybridEngine()
	if err != nil {
		t.Fatal(err)
	}
	alicePK := aliceEngine.GetPublicKey()
	if len(alicePK) != 1216 {
		t.Fatalf("taille PK Dual-768 Alice invalide: %d", len(alicePK))
	}

	// Bob initialise un moteur indépendant et chiffre pour Alice en utilisant sa clé publique
	bobEngine, err := newDualHybridEngine()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Message confidentiel chiffré par Bob pour la clé externe d'Alice")
	payload, err := crypto.Encrypt(ctx, bobEngine, message, alicePK)
	if err != nil {
		t.Fatalf("échec chiffrement pour clé externe: %v", err)
	}

	// Alice déchiffre avec sa clé privée
	decrypted, err := crypto.Decrypt(ctx, aliceEngine, payload)
	if err != nil {
		t.Fatalf("échec déchiffrement par Alice: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatal("message déchiffré ne correspond pas au message original")
	}

	// Eve tente de déchiffrer le message d'Alice
	eveEngine, err := newDualHybridEngine()
	if err != nil {
		t.Fatal(err)
	}
	_, err = crypto.Decrypt(ctx, eveEngine, payload)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: Eve a déchiffré un message destiné à Alice !")
	}
}

// TestSecurity_Dual1024_ExternalPublicKey valide le schéma complet Dual-1024 (X25519 + ML-KEM-1024)
// avec clé publique destinataire externe.
func TestSecurity_Dual1024_ExternalPublicKey(t *testing.T) {
	ctx := context.Background()

	// Alice (Dual-1024)
	aliceEngine, err := newDualHybrid1024Engine()
	if err != nil {
		t.Fatal(err)
	}
	alicePK := aliceEngine.GetPublicKey()
	if len(alicePK) != 1600 {
		t.Fatalf("taille PK Dual-1024 Alice invalide: %d (attendu 1600)", len(alicePK))
	}

	// Bob chiffre pour Alice
	bobEngine, err := newDualHybrid1024Engine()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Message d'évaluation confidentiel destiné exclusivement à Alice via Dual-1024")
	payload, err := crypto.Encrypt(ctx, bobEngine, message, alicePK)
	if err != nil {
		t.Fatalf("échec chiffrement Bob Dual-1024: %v", err)
	}

	// Alice déchiffre
	decrypted, err := crypto.Decrypt(ctx, aliceEngine, payload)
	if err != nil {
		t.Fatalf("échec déchiffrement Alice Dual-1024: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatal("incohérence texte déchiffré Dual-1024")
	}

	// Eve tente de déchiffrer
	eveEngine, err := newDualHybrid1024Engine()
	if err != nil {
		t.Fatal(err)
	}
	_, err = crypto.Decrypt(ctx, eveEngine, payload)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: Eve a déchiffré le message Dual-1024 !")
	}
}

// TestSecurity_RecipientPKMutationRefused teste la résistance cryptographique
// à la falsification ou mutation de la clé publique destinataire.
func TestSecurity_RecipientPKMutationRefused(t *testing.T) {
	ctx := context.Background()

	// 1. Test au niveau combiné KEM direct
	dualKEM, err := newDualHybridKEM()
	if err != nil {
		t.Fatal(err)
	}
	pk := dualKEM.PublicKey()

	// Mutation de la clé publique de 1 bit dans la partie X25519
	mutatedPK := append([]byte(nil), pk...)
	mutatedPK[0] ^= 0x01

	encapKey, bobSharedSecret, err := dualKEM.Encapsulate(ctx, mutatedPK)
	if err != nil {
		t.Logf("Encapsulation avec clé mutée rejetée (normal si point hors courbe): %v", err)
	} else {
		aliceSharedSecret, decErr := dualKEM.Decapsulate(ctx, encapKey)
		if decErr != nil {
			t.Logf("Décapsulation rejetée: %v", decErr)
		} else if bytes.Equal(bobSharedSecret, aliceSharedSecret) {
			t.Fatal("SÉCURITÉ VIOLÉE: Le combinateur a dérivé le même secret malgré une mutation de recipientPK !")
		}
	}

	// 2. Test au niveau de l'Engine complet
	aliceEngine, _ := newDualHybridEngine()
	bobEngine, _ := newDualHybridEngine()

	plain := []byte("Secret d'état inviolable")
	payload, err := crypto.Encrypt(ctx, aliceEngine, plain, aliceEngine.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}

	_, err = crypto.Decrypt(ctx, bobEngine, payload)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE: Déchiffrement réussi avec une mauvaise clé destinataire !")
	}
}

// TestSecurity_DirectCanonicalTranscript teste directement les fonctions BuildAAD,
// BuildTranscriptSalt et CombineHybridSecrets pour valider la structure TLV et les contrôles stricts.
func TestSecurity_DirectCanonicalTranscript(t *testing.T) {
	algo := "DUAL-X25519+ML-KEM-768"
	usage := crypto.UsageDataEncryption
	encap := bytes.Repeat([]byte{0xAA}, 1120)
	pk := bytes.Repeat([]byte{0xBB}, 1216)

	// AAD et Salt de base
	aad1 := crypto.BuildAAD(algo, usage, encap, pk)
	salt1 := crypto.BuildTranscriptSalt(algo, usage, encap, pk)

	if len(aad1) != 32 || len(salt1) != 32 {
		t.Fatalf("tailles de hash invalides: aad=%d, salt=%d", len(aad1), len(salt1))
	}

	// Isolation AAD vs Salt
	if bytes.Equal(aad1, salt1) {
		t.Fatal("AAD et TranscriptSalt ne doivent pas être identiques (séparation des étiquettes)")
	}

	// Sensibilité au changement d'algorithme
	aadDiffAlgo := crypto.BuildAAD("DUAL-X25519+ML-KEM-1024", usage, encap, pk)
	if bytes.Equal(aad1, aadDiffAlgo) {
		t.Fatal("BuildAAD insensible au changement d'algorithme")
	}

	// Sensibilité au changement d'usage
	aadDiffUsage := crypto.BuildAAD(algo, crypto.UsageKeyWrapping, encap, pk)
	if bytes.Equal(aad1, aadDiffUsage) {
		t.Fatal("BuildAAD insensible au changement de domaine d'usage")
	}

	// Sensibilité au changement d'encapKey
	encapMut := append([]byte(nil), encap...)
	encapMut[0] ^= 0xFF
	aadDiffEncap := crypto.BuildAAD(algo, usage, encapMut, pk)
	if bytes.Equal(aad1, aadDiffEncap) {
		t.Fatal("BuildAAD insensible à la modification d'encapKey")
	}

	// Sensibilité au changement de recipientPK
	pkMut := append([]byte(nil), pk...)
	pkMut[0] ^= 0xFF
	aadDiffPK := crypto.BuildAAD(algo, usage, encap, pkMut)
	if bytes.Equal(aad1, aadDiffPK) {
		t.Fatal("BuildAAD insensible à la modification de recipientPK")
	}

	// Test anti-collision de concaténation (propriété canonique TLV)
	hash1 := crypto.HashCanonicalTranscript("TEST", "A", "BC", []byte("1"), []byte("2"))
	hash2 := crypto.HashCanonicalTranscript("TEST", "AB", "C", []byte("1"), []byte("2"))
	if bytes.Equal(hash1, hash2) {
		t.Fatal("COLLISION DÉTECTÉE: HashCanonicalTranscript vulnérable à l'ambiguïté de découpage sans TLV !")
	}

	// Tests directs de validation des paramètres de CombineSecrets
	kemDual, err := crypto.NewDualHybrid(mlkem768.Scheme(), "DUAL-X25519+ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	xSS := make([]byte, 32)
	mlSS := make([]byte, 32)
	validEncap := make([]byte, 1120)
	validPK := make([]byte, 1216)

	// xSS invalide
	_, err = kemDual.CombineSecrets(make([]byte, 16), mlSS, validEncap, validPK)
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Errorf("attendu ErrInvalidKey sur xSS court, obtenu: %v", err)
	}

	// mlSS invalide
	_, err = kemDual.CombineSecrets(xSS, make([]byte, 48), validEncap, validPK)
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Errorf("attendu ErrInvalidKey sur mlSS invalide, obtenu: %v", err)
	}

	// encapKey de taille erronée
	_, err = kemDual.CombineSecrets(xSS, mlSS, make([]byte, 100), validPK)
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Errorf("attendu ErrInvalidKey sur encapKey erroné, obtenu: %v", err)
	}

	// recipientPK de taille erronée
	_, err = kemDual.CombineSecrets(xSS, mlSS, validEncap, make([]byte, 50))
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Errorf("attendu ErrInvalidKey sur recipientPK erroné, obtenu: %v", err)
	}

	// Appel valide
	sec, err := kemDual.CombineSecrets(xSS, mlSS, validEncap, validPK)
	if err != nil {
		t.Fatalf("échec CombineSecrets sur paramètres valides: %v", err)
	}
	if len(sec) != 32 {
		t.Fatalf("taille de secret combiné invalide: %d (attendu 32)", len(sec))
	}
}

// TestSecurity_NonRegressionExpectedSizes vérifie les tailles exactes de chaque algorithme
// pour garantir l'absence de régression de format.
func TestSecurity_NonRegressionExpectedSizes(t *testing.T) {
	// 1. Constantes symétriques
	if crypto.AES256KeySize != 32 {
		t.Errorf("AES256KeySize: %d, attendu 32", crypto.AES256KeySize)
	}
	if crypto.GCMNonceSize != 12 {
		t.Errorf("GCMNonceSize: %d, attendu 12", crypto.GCMNonceSize)
	}

	// 2. ML-KEM-768 (NIST FIPS 203)
	eng768, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}
	pk768 := eng768.GetPublicKey()
	if len(pk768) != 1184 {
		t.Errorf("ML-KEM-768 PK: %d, attendu 1184", len(pk768))
	}
	exp768 := eng768.(crypto.KeyExporter)
	_, sk768, _ := exp768.ExportKeys()
	if len(sk768) != 2400 {
		t.Errorf("ML-KEM-768 SK: %d, attendu 2400", len(sk768))
	}

	// 3. ML-KEM-1024 (NIST FIPS 203 Catégorie 5)
	eng1024, err := newMLKEM1024Engine()
	if err != nil {
		t.Fatal(err)
	}
	pk1024 := eng1024.GetPublicKey()
	if len(pk1024) != 1568 {
		t.Errorf("ML-KEM-1024 PK: %d, attendu 1568", len(pk1024))
	}
	exp1024 := eng1024.(crypto.KeyExporter)
	_, sk1024, _ := exp1024.ExportKeys()
	if len(sk1024) != 3168 {
		t.Errorf("ML-KEM-1024 SK: %d, attendu 3168", len(sk1024))
	}

	// 4. DUAL-X25519+ML-KEM-768
	engDual768, err := newDualHybridEngine()
	if err != nil {
		t.Fatal(err)
	}
	pkDual768 := engDual768.GetPublicKey()
	if len(pkDual768) != 1216 {
		t.Errorf("Dual-768 PK: %d, attendu 1216", len(pkDual768))
	}
	expDual768 := engDual768.(crypto.KeyExporter)
	_, skDual768, _ := expDual768.ExportKeys()
	if len(skDual768) != 2432 {
		t.Errorf("Dual-768 SK: %d, attendu 2432", len(skDual768))
	}

	// 5. DUAL-X25519+ML-KEM-1024
	engDual1024, err := newDualHybrid1024Engine()
	if err != nil {
		t.Fatal(err)
	}
	pkDual1024 := engDual1024.GetPublicKey()
	if len(pkDual1024) != 1600 {
		t.Errorf("Dual-1024 PK: %d, attendu 1600", len(pkDual1024))
	}
	expDual1024 := engDual1024.(crypto.KeyExporter)
	_, skDual1024, _ := expDual1024.ExportKeys()
	if len(skDual1024) != 3200 {
		t.Errorf("Dual-1024 SK: %d, attendu 3200", len(skDual1024))
	}
}

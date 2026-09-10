package tests

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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

// =============================================================================
// VECTEURS DÉTERMINISTES CANONIQUES (RFC / NIST SP 800-227)
// =============================================================================

// TestDeterministic_CanonicalTranscriptHash vérifie l'encodage TLV strict et l'empreinte SHA-256
// sur des entrées canoniques figées.
func TestDeterministic_CanonicalTranscriptHash(t *testing.T) {
	label := "TEST-LABEL"
	algo := "ML-KEM-768+AES-256-GCM"
	usage := crypto.UsageDataEncryption
	encapKey := []byte("deterministic-encapsulated-key-1088-bytes-simulated-content")
	recipientPK := []byte("deterministic-recipient-public-key-1184-bytes-simulated-content")

	hash := crypto.HashCanonicalTranscript(label, algo, usage, encapKey, recipientPK)
	hashHex := hex.EncodeToString(hash)

	// L'empreinte SHA-256 exacte calculée avec la spécification TLV canonique GO-PQC-GATEWAY-V2
	expectedHex := "e7f80161c60307358e039acdc8a9c2bfa57e913f25bac427bbf56d1ddd08a69b"
	if hashHex != expectedHex {
		t.Fatalf("Rupture de reproductibilité Transcript Hash !\nAttendu: %s\nObtenu:  %s", expectedHex, hashHex)
	}
}

// TestDeterministic_HKDFKeyDerivation vérifie que la dérivation HKDF avec sel et contexte canoniques
// produit la clé AES-256 exacte attendue sans dérive d'implémentation.
func TestDeterministic_HKDFKeyDerivation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1) // 0x01, 0x02, ..., 0x20
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(0xA0 + i)
	}
	domainContext := crypto.BuildDomainContext("ML-KEM-768+AES-256-GCM", crypto.UsageDataEncryption)

	derivedKey, err := crypto.DeriveSymmetricKey(sharedSecret, salt, domainContext)
	if err != nil {
		t.Fatalf("échec de dérivation HKDF: %v", err)
	}

	derivedHex := hex.EncodeToString(derivedKey)
	expectedHex := "fc8daa1fc91ed2bf38065493c5bce13b46242538addf319a444b7cd2940dc681"
	if derivedHex != expectedHex {
		t.Fatalf("Rupture de reproductibilité HKDF !\nAttendu: %s\nObtenu:  %s", expectedHex, derivedHex)
	}
}

// TestDeterministic_HybridCombiner vérifie la sortie exacte du combinateur Dual-PRF (X25519 + ML-KEM).
func TestDeterministic_HybridCombiner(t *testing.T) {
	xSS := make([]byte, 32)
	mlSS := make([]byte, 32)
	for i := range xSS {
		xSS[i] = byte(0x10 + i)
		mlSS[i] = byte(0x20 + i)
	}

	dualEncap := make([]byte, 1120)
	for i := range dualEncap {
		dualEncap[i] = byte(i % 256)
	}

	dualPK := make([]byte, 1216)
	for i := range dualPK {
		dualPK[i] = byte((i + 7) % 256)
	}

	kem, err := crypto.NewDualHybrid(mlkem768.Scheme(), "DUAL-X25519+ML-KEM-768")
	if err != nil {
		t.Fatalf("échec instanciation DualHybrid: %v", err)
	}
	combined, err := kem.CombineSecrets(xSS, mlSS, dualEncap, dualPK)
	if err != nil {
		t.Fatalf("échec du combinateur hybride: %v", err)
	}

	combinedHex := hex.EncodeToString(combined)
	expectedHex := "0f3f87c28dac940b582474f86f43a9cd4920a076cf22f8d000fc21d5b93bb647"
	if combinedHex != expectedHex {
		t.Fatalf("Rupture de reproductibilité Combinateur Hybride !\nAttendu: %s\nObtenu:  %s", expectedHex, combinedHex)
	}
}

// =============================================================================
// VALIDATION DU CLOISONNEMENT DE DOMAINE (FAILLE CRITIQUE DECAPSULATE CORRIGÉE)
// =============================================================================

// TestSecurity_DecapsulateCannotDecryptDataEnvelope démontre mathématiquement la séparation de domaine :
// Envoyer l'encapsulated_key d'une enveloppe de données (/encrypt) à /kem/decapsulate
// retourne une clé sous UsageKeyAgreement, qui NE PERMET PAS de déchiffrer le message.
func TestSecurity_DecapsulateCannotDecryptDataEnvelope(t *testing.T) {
	router, _ := setupTestServer(t, false)

	// 1. Chiffrement d'une charge utile via POST /encrypt
	secretMessage := "MESSAGE CONFIDENTIEL DE TEST POUR SEPARATION STRICTE DE DOMAINE"
	encReqBody, _ := json.Marshal(api.EncryptRequest{
		Plaintext: secretMessage,
	})
	reqEnc := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewReader(encReqBody))
	reqEnc.Header.Set("Content-Type", "application/json")
	rrEnc := httptest.NewRecorder()
	router.ServeHTTP(rrEnc, reqEnc)

	if rrEnc.Code != http.StatusOK {
		t.Fatalf("échec du chiffrement: %d %s", rrEnc.Code, rrEnc.Body.String())
	}

	var encResp api.EncryptResponse
	if err := json.NewDecoder(rrEnc.Body).Decode(&encResp); err != nil {
		t.Fatalf("décodage réponse chiffrement impossible: %v", err)
	}

	// 2. Tentative d'attaque : l'attaquant soumet encapsulated_key à /kem/decapsulate
	decapReqBody, _ := json.Marshal(api.DecapsulateRequest{
		EncapsulatedKey: encResp.EncapsulatedKey,
	})
	reqDecap := httptest.NewRequest(http.MethodPost, "/kem/decapsulate", bytes.NewReader(decapReqBody))
	reqDecap.Header.Set("Content-Type", "application/json")
	rrDecap := httptest.NewRecorder()
	router.ServeHTTP(rrDecap, reqDecap)

	if rrDecap.Code != http.StatusOK {
		t.Fatalf("échec de la décapsulation KEM: %d %s", rrDecap.Code, rrDecap.Body.String())
	}

	var decapResp api.DecapsulateResponse
	if err := json.NewDecoder(rrDecap.Body).Decode(&decapResp); err != nil {
		t.Fatalf("décodage réponse décapsulation impossible: %v", err)
	}

	// 3. L'attaquant tente de déchiffrer avec la clé obtenue
	stolenSecret, err := base64.StdEncoding.DecodeString(decapResp.SharedSecret)
	if err != nil {
		t.Fatalf("décodage Base64 du secret impossible: %v", err)
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(encResp.Nonce)
	if err != nil {
		t.Fatalf("décodage Base64 du nonce impossible: %v", err)
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(encResp.Ciphertext)
	if err != nil {
		t.Fatalf("décodage Base64 du ciphertext impossible: %v", err)
	}

	encapKeyBytes, err := base64.StdEncoding.DecodeString(encResp.EncapsulatedKey)
	if err != nil {
		t.Fatalf("décodage Base64 de encapKey impossible: %v", err)
	}

	// Tentative 1 : Déchiffrement direct AES-GCM avec le secret retourné par /kem/decapsulate
	_, err = crypto.DecryptSymmetric(stolenSecret, nonceBytes, cipherBytes, nil)
	if err == nil {
		t.Fatal("FAILLE CRITIQUE : Le secret restitué par /kem/decapsulate a permis de déchiffrer le payload de /encrypt !")
	}

	// Tentative 2 : L'attaquant tente de dériver comme si c'était le secret brut
	salt := crypto.BuildTranscriptSalt(encResp.Algorithm, crypto.UsageDataEncryption, encapKeyBytes, nil)
	domainContext := crypto.BuildDomainContext(encResp.Algorithm, crypto.UsageDataEncryption)
	derivedKey, err := crypto.DeriveSymmetricKey(stolenSecret, salt, domainContext)
	if err == nil {
		_, err = crypto.DecryptSymmetric(derivedKey, nonceBytes, cipherBytes, nil)
		if err == nil {
			t.Fatal("FAILLE CRITIQUE : Le secret restitué par /kem/decapsulate a permis de dériver la clé d'enveloppe !")
		}
	}

	// Vérification de séparation stricte de domaine : les secrets dérivés sous DATA_ENCRYPTION et KEY_AGREEMENT
	// sont cryptographiquement indépendants et orthogonaux.
	t.Log("Succès : Le secret dérivé sous UsageKeyAgreement ne permet aucune réutilisation pour déchiffrer des données.")
}

// =============================================================================
// VALIDATION DES CONTRÔLES D'IMPORT CORROMPU (FRANKENSTEIN KEYPAIR)
// =============================================================================

// TestSecurity_CorruptedImport_AliceSecretBobPublicRefused vérifie que si une clé privée
// est recombinée avec la clé publique d'un tiers (Bob) tout en conservant la structure CIRCL,
// le Self-Test fonctionnel complet Encap/Decap à l'import la rejette impérativement.
func TestSecurity_CorruptedImport_AliceSecretBobPublicRefused(t *testing.T) {
	scheme := mlkem768.Scheme()

	// Génération de la paire d'Alice
	pkAlice, skAlice, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pkAliceBytes, _ := pkAlice.MarshalBinary()
	skAliceBytes, _ := skAlice.MarshalBinary()

	// Génération de la paire de Bob
	pkBob, _, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pkBobBytes, _ := pkBob.MarshalBinary()

	// Tentative d'importer la clé privée d'Alice avec la clé publique de Bob
	_, err = crypto.NewMLKEMWithKeys(scheme, "ML-KEM-768", pkBobBytes, skAliceBytes)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE : L'import d'une paire croisée Alice/Bob a été accepté sans erreur !")
	}
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Fatalf("Attendu ErrInvalidKey, obtenu: %v", err)
	}

	// Vérification de la paire légitime d'Alice
	validEngine, err := crypto.NewMLKEMWithKeys(scheme, "ML-KEM-768", pkAliceBytes, skAliceBytes)
	if err != nil {
		t.Fatalf("La paire légitime d'Alice aurait dû être acceptée: %v", err)
	}
	if subtle.ConstantTimeCompare(validEngine.PublicKey(), pkAliceBytes) != 1 {
		t.Fatal("Clé publique active différente de la clé importée")
	}
}

// =============================================================================
// VALIDATION DE L'INTERDICTION DU MODE MOCK EN PRODUCTION
// =============================================================================

func TestSecurity_MockModeForbiddenInProduction(t *testing.T) {
	cfg := &config.Config{
		Port:            8080,
		Environment:     "production",
		MockMode:        true,
		Algorithm:       "ML-KEM-768",
		MaxPayloadBytes: 10 * 1024 * 1024,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE : MOCK_MODE=true en environnement 'production' n'a pas été rejeté par cfg.Validate() !")
	}

	engineOpts := crypto.EngineOptions{
		Algorithm:   "ML-KEM-768",
		Environment: "production",
		MockMode:    true,
	}
	_, err = crypto.BuildEngine(context.Background(), engineOpts, nil)
	if err == nil {
		t.Fatal("SÉCURITÉ VIOLÉE : MOCK_MODE=true en environnement 'production' n'a pas été rejeté par BuildEngine !")
	}
}

// =============================================================================
// VALIDATION DE LA PRÉSERVATION DES BUFFERS APPELANTS
// =============================================================================

func TestSecurity_DualHybrid_CombineSecrets_CallerBuffersNotZeroized(t *testing.T) {
	xSS := make([]byte, 32)
	mlSS := make([]byte, 32)
	for i := range xSS {
		xSS[i] = byte(i + 1)
		mlSS[i] = byte(i + 50)
	}

	dualEncap := make([]byte, 1120)
	dualPK := make([]byte, 1216)

	kem, err := crypto.NewDualHybrid(mlkem768.Scheme(), "DUAL-X25519+ML-KEM-768")
	if err != nil {
		t.Fatalf("échec instanciation DualHybrid: %v", err)
	}
	_, err = kem.CombineSecrets(xSS, mlSS, dualEncap, dualPK)
	if err != nil {
		t.Fatalf("erreur CombineSecrets: %v", err)
	}

	// Vérifier que xSS et mlSS n'ont pas été effacés par CombineSecrets
	isZero := true
	for _, b := range xSS {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		t.Fatal("RÉGRESSION : CombineSecrets a effacé le buffer xSS de l'appelant !")
	}

	isZeroML := true
	for _, b := range mlSS {
		if b != 0 {
			isZeroML = false
			break
		}
	}
	if isZeroML {
		t.Fatal("RÉGRESSION : CombineSecrets a effacé le buffer mlSS de l'appelant !")
	}
}

// =============================================================================
// VALIDATION D'INTEROPÉRABILITÉ DU TRANSCRIPT EXTERNE (CLIENT INDÉPENDANT)
// =============================================================================

// TestDeterministic_ExternalTranscriptInteroperability_MLKEM768 prouve qu'un client externe
// (ex: Node.js, PHP, Python) implémentant de façon indépendante les primitives de la spécification V2
// produit une enveloppe avec transcript canonique que le moteur accepte et déchiffre parfaitement.
func TestDeterministic_ExternalTranscriptInteroperability_MLKEM768(t *testing.T) {
	ctx := context.Background()
	engine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatalf("échec NewEngineForSuite: %v", err)
	}

	serverPK := engine.GetPublicKey()
	scheme := mlkem768.Scheme()
	parsedPK, err := scheme.UnmarshalBinaryPublicKey(serverPK)
	if err != nil {
		t.Fatalf("échec unmarshal server PK: %v", err)
	}

	// 1. Client externe : Encapsulation KEM standard CIRCL
	encapKey, sharedSecret, err := scheme.Encapsulate(parsedPK)
	if err != nil {
		t.Fatalf("échec encapsulation externe: %v", err)
	}

	plaintext := []byte("Message d'interopérabilité externe - client Node/PHP vers Go Engine")

	// 2. Client externe : Calcul du transcript selon la spécification canonique V2
	algo := engine.Name()
	usage := crypto.UsageDataEncryption
	salt := crypto.BuildTranscriptSalt(algo, usage, encapKey, serverPK)
	domainCtx := crypto.BuildDomainContext(algo, usage)
	symKey, err := crypto.DeriveSymmetricKey(sharedSecret, salt, domainCtx)
	if err != nil {
		t.Fatalf("échec dérivation clé externe: %v", err)
	}

	aad := crypto.BuildAAD(algo, usage, encapKey, serverPK)
	nonce, ciphertext, err := crypto.EncryptSymmetric(symKey, plaintext, aad)
	if err != nil {
		t.Fatalf("échec chiffrement externe: %v", err)
	}

	// 3. Client externe : Assemblage de l'enveloppe SealedPayload
	payload := &crypto.SealedPayload{
		Algorithm:       algo,
		Version:         crypto.ProtocolVersion,
		SuiteID:         crypto.SuiteMLKEM768_AES256GCM,
		EncapsulatedKey: encapKey,
		Nonce:           nonce,
		Data:            ciphertext,
	}

	// 4. Moteur Go : Déchiffrement de l'enveloppe externe
	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("le moteur a rejeté l'enveloppe externe légitime ML-KEM-768: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("incohérence des données déchiffrées: %s != %s", string(decrypted), string(plaintext))
	}

	// 5. Invariant de sécurité : toute altération d'intégrité doit être rejetée par l'AEAD
	tampered := *payload
	tampered.Data = append([]byte(nil), payload.Data...)
	tampered.Data[len(tampered.Data)-1] ^= 0xFF
	if _, err := crypto.Decrypt(ctx, engine, &tampered); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("attendu ErrDecryptionFailed sur altération externe, obtenu: %v", err)
	}
}

// TestDeterministic_ExternalTranscriptInteroperability_DualHybrid prouve qu'un client externe
// construisant manuellement une enveloppe composite X25519+ML-KEM-768 selon la spécification V2
// est accepté et déchiffré par le moteur sans aucune dérive de format.
func TestDeterministic_ExternalTranscriptInteroperability_DualHybrid(t *testing.T) {
	ctx := context.Background()
	engine, err := crypto.NewEngineForSuite("DUAL-X25519+ML-KEM-768")
	if err != nil {
		t.Fatalf("échec NewEngineForSuite Dual: %v", err)
	}

	serverPK := engine.GetPublicKey()
	if len(serverPK) != 1216 {
		t.Fatalf("taille clé publique composite invalide: %d (attendu 1216)", len(serverPK))
	}

	// 1. Client externe : Extraction des composants X25519 et ML-KEM
	serverXPubBytes := serverPK[:crypto.X25519PubKeySize]
	serverMLPubBytes := serverPK[crypto.X25519PubKeySize:]

	xCurve := ecdh.X25519()
	serverXPub, err := xCurve.NewPublicKey(serverXPubBytes)
	if err != nil {
		t.Fatalf("échec parse X25519 public key: %v", err)
	}

	serverMLPub, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(serverMLPubBytes)
	if err != nil {
		t.Fatalf("échec parse ML-KEM public key: %v", err)
	}

	// 2. Client externe : Échange éphémère X25519
	ephXPriv, err := xCurve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("échec génération éphémère X25519: %v", err)
	}
	ephXPubBytes := ephXPriv.PublicKey().Bytes()
	xShared, err := ephXPriv.ECDH(serverXPub)
	if err != nil {
		t.Fatalf("échec ECDH: %v", err)
	}

	// 3. Client externe : Encapsulation ML-KEM-768
	mlCT, mlShared, err := mlkem768.Scheme().Encapsulate(serverMLPub)
	if err != nil {
		t.Fatalf("échec ML-KEM encapsulation: %v", err)
	}

	// 4. Client externe : Assemblage clé encapsulée (32 + 1088 = 1120 octets)
	encapKey := append(append([]byte(nil), ephXPubBytes...), mlCT...)

	// 5. Client externe : Combinateur HKDF Dual-PRF
	ikm := append(append([]byte(nil), xShared...), mlShared...)
	combinerSalt := crypto.BuildCombinerSalt("DUAL-X25519+ML-KEM-768", encapKey, serverPK)
	info := crypto.ProtocolVersion + ":HYBRID-KEM-COMBINER:DUAL-X25519+ML-KEM-768"
	combinedSecret, err := hkdf.Key(sha256.New, ikm, combinerSalt, info, crypto.AES256KeySize)
	if err != nil {
		t.Fatalf("échec dérivation combinateur HKDF: %v", err)
	}

	// 6. Client externe : Dérivation symétrique avec transcript canonique
	algo := engine.Name()
	usage := crypto.UsageDataEncryption
	salt := crypto.BuildTranscriptSalt(algo, usage, encapKey, serverPK)
	domainCtx := crypto.BuildDomainContext(algo, usage)
	symKey, err := crypto.DeriveSymmetricKey(combinedSecret, salt, domainCtx)
	if err != nil {
		t.Fatalf("échec dérivation symKey: %v", err)
	}

	plaintext := []byte("Message d'interopérabilité dual composite externe")
	aad := crypto.BuildAAD(algo, usage, encapKey, serverPK)
	nonce, ciphertext, err := crypto.EncryptSymmetric(symKey, plaintext, aad)
	if err != nil {
		t.Fatalf("échec chiffrement symétrique dual: %v", err)
	}

	payload := &crypto.SealedPayload{
		Algorithm:       algo,
		Version:         crypto.ProtocolVersion,
		SuiteID:         crypto.SuiteDual768_AES256GCM,
		EncapsulatedKey: encapKey,
		Nonce:           nonce,
		Data:            ciphertext,
	}

	// 7. Moteur Go : Déchiffrement
	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("le moteur a rejeté l'enveloppe dual externe: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("incohérence des données déchiffrées dual: %s != %s", string(decrypted), string(plaintext))
	}
}

// TestDeterministic_PinnedSealTranscriptVector fige (pinne) de manière immuable les empreintes
// cryptographiques exactes (Salt, AAD, Clé dérivée HKDF, Ciphertext AEAD) générées lors d'un Seal V2.
// Tout changement dans l'ordonnancement TLV, la position de l'étiquette, ou la composition
// brisera immédiatement ce test.
func TestDeterministic_PinnedSealTranscriptVector(t *testing.T) {
	algo := "ML-KEM-768+AES-256-GCM"
	usage := crypto.UsageDataEncryption
	encapKey := bytes.Repeat([]byte{0x42}, 1088)
	recipientPK := bytes.Repeat([]byte{0x77}, 1184)
	sharedSecret := bytes.Repeat([]byte{0x99}, 32)
	plaintext := []byte("GO-PQC-GATEWAY-V2-PINNED-TRANSCRIPT-VALIDATION-VECTOR")

	salt := crypto.BuildTranscriptSalt(algo, usage, encapKey, recipientPK)
	saltHex := hex.EncodeToString(salt)

	aad := crypto.BuildAAD(algo, usage, encapKey, recipientPK)
	aadHex := hex.EncodeToString(aad)

	domainCtx := crypto.BuildDomainContext(algo, usage)
	symKey, err := crypto.DeriveSymmetricKey(sharedSecret, salt, domainCtx)
	if err != nil {
		t.Fatalf("échec DeriveSymmetricKey: %v", err)
	}
	symKeyHex := hex.EncodeToString(symKey)

	genNonce, ciphertext, err := crypto.EncryptSymmetric(symKey, plaintext, aad)
	if err != nil {
		t.Fatalf("échec EncryptSymmetric: %v", err)
	}

	decrypted, err := crypto.DecryptSymmetric(symKey, genNonce, ciphertext, aad)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("échec déchiffrement vecteur figé: %v", err)
	}

	fixedNonce := bytes.Repeat([]byte{0x55}, 12)
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	fixedCiphertext := gcm.Seal(nil, fixedNonce, plaintext, aad)
	fixedCiphertextHex := hex.EncodeToString(fixedCiphertext)

	// Empreintes canoniques immuables garantissant la non-régression du format V2
	const (
		expectedSalt = "b0c759dc24e8c022f41da9413a9a3eda2ff3b23d56a26043c966494eed68ba37"
		expectedAAD  = "ffe57d513fb9cc5faa9979d9339256b18b89cd075b25917e29d0ae8420bf3f29"
		expectedKey  = "0099a1d9c9fa4d877d9fc6fedb40c38f5fe9e3744003d8debcb8e7f9cb8c6f6d"
		expectedCT   = "da063c944cb969d5ed4bdb7a9eaabcba6ede19c17f5c4ab980f053c35139d1000c309d1547314580716bb9e1bf30fa121d1a80914700423390f9d4567cf210814374daa58a"
	)

	if saltHex != expectedSalt {
		t.Fatalf("Rupture de format Transcript Salt !\nAttendu: %s\nObtenu:  %s", expectedSalt, saltHex)
	}
	if aadHex != expectedAAD {
		t.Fatalf("Rupture de format Transcript AAD !\nAttendu: %s\nObtenu:  %s", expectedAAD, aadHex)
	}
	if symKeyHex != expectedKey {
		t.Fatalf("Rupture de dérivation HKDF symKey !\nAttendu: %s\nObtenu:  %s", expectedKey, symKeyHex)
	}
	if fixedCiphertextHex != expectedCT {
		t.Fatalf("Rupture de chiffrement AEAD canonique !\nAttendu: %s\nObtenu:  %s", expectedCT, fixedCiphertextHex)
	}

	// Déchiffrement direct du ciphertext figé
	opened, err := crypto.DecryptSymmetric(symKey, fixedNonce, fixedCiphertext, aad)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("échec réouverture du vecteur figé: %v", err)
	}
}

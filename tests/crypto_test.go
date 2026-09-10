package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"pq-crypto-service/internal/crypto"
)

func TestMLKEMEngine_KeyGeneration(t *testing.T) {
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("échec d'initialisation du moteur ML-KEM-768: %v", err)
	}

	pk := engine.GetPublicKey()
	if len(pk) == 0 {
		t.Fatal("la clé publique ML-KEM-768 ne doit pas être vide")
	}

	// Taille standard pour ML-KEM-768 (NIST FIPS 203) = 1184 octets
	if len(pk) != 1184 {
		t.Errorf("taille de clé publique inattendue: obtenu %d octets, attendu 1184", len(pk))
	}

	if engine.IsMock() {
		t.Error("IsMock() doit retourner false pour MLKEMEngine")
	}
}

func TestMLKEMEngine_EncryptDecryptRoundtrip(t *testing.T) {
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("échec d'initialisation: %v", err)
	}

	ctx := context.Background()
	originalMessage := []byte("Message ultra-secret protégé contre la menace des ordinateurs quantiques !")

	// 1. Chiffrement
	payload, err := crypto.Encrypt(ctx, engine, originalMessage, nil)
	if err != nil {
		t.Fatalf("échec de chiffrement: %v", err)
	}

	if len(payload.EncapsulatedKey) == 0 {
		t.Fatal("la clé encapsulée ne doit pas être vide")
	}
	if len(payload.Nonce) != 12 {
		t.Fatalf("taille de nonce GCM invalide: %d (attendu 12)", len(payload.Nonce))
	}
	if len(payload.Data) == 0 {
		t.Fatal("le texte chiffré ne doit pas être vide")
	}

	// 2. Déchiffrement
	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("échec de déchiffrement: %v", err)
	}

	if !bytes.Equal(originalMessage, decrypted) {
		t.Fatalf("le message déchiffré ne correspond pas à l'original.\nObtenu: %s\nAttendu: %s", string(decrypted), string(originalMessage))
	}
}

func TestMLKEMEngine_EncryptWithExternalPublicKey(t *testing.T) {
	aliceEngine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("échec initialisation Alice: %v", err)
	}

	bobEngine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("échec initialisation Bob: %v", err)
	}

	ctx := context.Background()
	secretData := []byte("Données confidentielles destinées exclusivement à Bob")

	// Alice chiffre pour Bob en utilisant la clé publique de Bob
	bobPK := bobEngine.GetPublicKey()
	payload, err := crypto.Encrypt(ctx, aliceEngine, secretData, bobPK)
	if err != nil {
		t.Fatalf("Alice n'a pas pu chiffrer avec la clé de Bob: %v", err)
	}

	// Bob déchiffre avec sa clé privée
	decrypted, err := crypto.Decrypt(ctx, bobEngine, payload)
	if err != nil {
		t.Fatalf("Bob n'a pas pu déchiffrer: %v", err)
	}

	if !bytes.Equal(secretData, decrypted) {
		t.Fatalf("incohérence des données déchiffrées par Bob")
	}

	// Alice ne doit PAS pouvoir déchiffrer ce payload (clé privée différente)
	_, err = crypto.Decrypt(ctx, aliceEngine, payload)
	if err == nil {
		t.Fatal("Alice ne devrait pas pouvoir déchiffrer un message destiné à Bob")
	}
}

func TestMLKEMEngine_TamperedCiphertext(t *testing.T) {
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("erreur: %v", err)
	}

	ctx := context.Background()
	original := []byte("Message pour test d'intégrité")

	payload, err := crypto.Encrypt(ctx, engine, original, nil)
	if err != nil {
		t.Fatalf("erreur chiffrement: %v", err)
	}

	// Altération d'un octet du Ciphertext
	payload.Data[0] ^= 0xFF

	_, err = crypto.Decrypt(ctx, engine, payload)
	if err == nil {
		t.Fatal("le déchiffrement d'un texte chiffré altéré DOIT échouer (intégrité AEAD violée)")
	}
}

func TestMLKEMEngine_TamperedNonce(t *testing.T) {
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("erreur: %v", err)
	}

	ctx := context.Background()
	original := []byte("Message pour test de nonce")

	payload, err := crypto.Encrypt(ctx, engine, original, nil)
	if err != nil {
		t.Fatalf("erreur chiffrement: %v", err)
	}

	// Altération du Nonce
	payload.Nonce[0] ^= 0xAA

	_, err = crypto.Decrypt(ctx, engine, payload)
	if err == nil {
		t.Fatal("le déchiffrement avec un Nonce altéré DOIT échouer")
	}
}

func TestMLKEMEngine_EmptyPayload(t *testing.T) {
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("erreur: %v", err)
	}

	_, err = crypto.Encrypt(context.Background(), engine, []byte{}, nil)
	if err == nil {
		t.Fatal("le chiffrement d'une charge vide doit renvoyer une erreur")
	}
}

func TestMLKEMEngine_LargePayload(t *testing.T) {
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatalf("erreur: %v", err)
	}

	ctx := context.Background()
	// Génération de 2 Mo de données aléatoires
	largeData := make([]byte, 2*1024*1024)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("erreur génération aléatoire: %v", err)
	}

	payload, err := crypto.Encrypt(ctx, engine, largeData, nil)
	if err != nil {
		t.Fatalf("échec chiffrement 2 Mo: %v", err)
	}

	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("échec déchiffrement 2 Mo: %v", err)
	}

	if !bytes.Equal(largeData, decrypted) {
		t.Fatal("incohérence sur la charge utile de 2 Mo")
	}
}

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

func TestDualHybridEngine_KeyGeneration(t *testing.T) {
	engine, err := newDualHybridEngine()
	if err != nil {
		t.Fatalf("échec d'initialisation DualHybridEngine: %v", err)
	}

	pk := engine.GetPublicKey()
	// Taille attendue = 32 octets (X25519) + 1184 octets (ML-KEM-768) = 1216 octets
	if len(pk) != 1216 {
		t.Fatalf("taille de clé publique composite invalide: obtenu %d, attendu 1216", len(pk))
	}

	if engine.Name() != "DUAL-X25519+ML-KEM-768+AES-256-GCM" {
		t.Errorf("nom d'algorithme inattendu: %s", engine.Name())
	}
}

func TestDualHybridEngine_EncryptDecryptRoundtrip(t *testing.T) {
	engine, err := newDualHybridEngine()
	if err != nil {
		t.Fatalf("erreur: %v", err)
	}

	ctx := context.Background()
	secret := []byte("Payload confidentiel protégé par le mécanisme hybride post-quantique")

	payload, err := crypto.Encrypt(ctx, engine, secret, nil)
	if err != nil {
		t.Fatalf("erreur chiffrement dual: %v", err)
	}

	// Taille attendue de la clé encapsulée = 32 (X25519 éphémère) + 1088 (ML-KEM) = 1120 octets
	if len(payload.EncapsulatedKey) != 1120 {
		t.Fatalf("taille de clé encapsulée dual invalide: obtenu %d, attendu 1120", len(payload.EncapsulatedKey))
	}

	decrypted, err := crypto.Decrypt(ctx, engine, payload)
	if err != nil {
		t.Fatalf("erreur déchiffrement dual: %v", err)
	}

	if !bytes.Equal(secret, decrypted) {
		t.Fatalf("incohérence des données déchiffrées en mode dual")
	}
}

func TestDualHybridEngine_TamperedCiphertext(t *testing.T) {
	engine, err := newDualHybridEngine()
	if err != nil {
		t.Fatalf("erreur: %v", err)
	}

	ctx := context.Background()
	secret := []byte("Message pour test d'intégrité dual")

	payload, err := crypto.Encrypt(ctx, engine, secret, nil)
	if err != nil {
		t.Fatalf("erreur chiffrement: %v", err)
	}

	payload.Data[5] ^= 0xFF

	_, err = crypto.Decrypt(ctx, engine, payload)
	if err == nil {
		t.Fatal("le déchiffrement d'un texte altéré en mode dual DOIT échouer")
	}
}

func TestZeroize_MemoryWiped(t *testing.T) {
	sensitiveBuffer := []byte("CLE_SECRETE_TEMPORAIRE_A_DETRUIRE_IMMEDIATEMENT_1234567890")
	crypto.Zeroize(sensitiveBuffer)

	for i, b := range sensitiveBuffer {
		if b != 0 {
			t.Fatalf("l'octet à l'index %d n'a pas été remis à zéro (valeur: %d)", i, b)
		}
	}
}

func TestEngineOpen_MetadataVerification(t *testing.T) {
	ctx := context.Background()
	engine, err := newMLKEMEngine()
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("Message pour test métadonnées en défense en profondeur")
	sealed, err := crypto.Encrypt(ctx, engine, plain, nil)
	if err != nil {
		t.Fatal(err)
	}

	badVer := *sealed
	badVer.Version = "v99"
	if _, err := engine.Open(ctx, &badVer, crypto.UsageDataEncryption); !errors.Is(err, crypto.ErrMismatchedVersion) {
		t.Fatalf("attendu ErrMismatchedVersion, obtenu: %v", err)
	}

	badSuite := *sealed
	badSuite.SuiteID = crypto.SuiteDual1024_AES256GCM
	if _, err := engine.Open(ctx, &badSuite, crypto.UsageDataEncryption); !errors.Is(err, crypto.ErrMismatchedSuite) {
		t.Fatalf("attendu ErrMismatchedSuite, obtenu: %v", err)
	}

	badAlgo := *sealed
	badAlgo.Algorithm = "BAD-ALGO"
	if _, err := engine.Open(ctx, &badAlgo, crypto.UsageDataEncryption); !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
		t.Fatalf("attendu ErrUnsupportedAlgorithm, obtenu: %v", err)
	}

	decrypted, err := engine.Open(ctx, sealed, crypto.UsageDataEncryption)
	if err != nil || !bytes.Equal(decrypted, plain) {
		t.Fatalf("échec déchiffrement valide: %v", err)
	}
}

// TestEngineOpen_AllowLegacyPolicy valide que la politique allowLegacy s'applique directement au niveau du moteur Engine.Open.
func TestEngineOpen_AllowLegacyPolicy(t *testing.T) {
	ctx := context.Background()
	plain := []byte("secret-legacy-test")

	// Moteur strict (défaut)
	strictEngine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Encrypt(ctx, strictEngine, plain, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Payload altérée avec l'alias KEM au lieu du nom de suite canonique
	aliasPayload := *sealed
	aliasPayload.Algorithm = "ML-KEM-768"

	// Le moteur strict doit rejeter l'alias non canonique
	if _, err := strictEngine.Open(ctx, &aliasPayload, crypto.UsageDataEncryption); !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
		t.Fatalf("moteur strict: attendu ErrUnsupportedAlgorithm, obtenu: %v", err)
	}

	// Moteur permissif (allowLegacy = true) avec les mêmes clés
	exporter := strictEngine.(crypto.KeyExporter)
	pk, sk, _ := exporter.ExportKeys()
	permEngine, err := crypto.NewEngineWithKeysAndPolicy("ML-KEM-768", pk, sk, true)
	if err != nil {
		t.Fatal(err)
	}

	// Le moteur permissif doit accepter l'alias non canonique
	decrypted, err := permEngine.Open(ctx, &aliasPayload, crypto.UsageDataEncryption)
	if err != nil {
		t.Fatalf("moteur permissif: échec déchiffrement avec alias: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("données déchiffrées incorrectes")
	}
}

// TestHybridEngine_UnwrapKey_StrictModeRoundtrip valide que l'API UnwrapKey fonctionne en mode strict par défaut.
func TestHybridEngine_UnwrapKey_StrictModeRoundtrip(t *testing.T) {
	ctx := context.Background()
	engine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatalf("échec NewEngineForSuite: %v", err)
	}

	dek := []byte("01234567890123456789012345678901") // 32 octets AES-256
	wrapped, err := crypto.WrapKey(ctx, engine, dek, nil)
	if err != nil {
		t.Fatalf("échec WrapKey: %v", err)
	}

	unwrapped, err := crypto.UnwrapKey(ctx, engine, wrapped.EncapsulatedKey, wrapped.Nonce, wrapped.Data)
	if err != nil {
		t.Fatalf("échec UnwrapKey en mode strict: %v", err)
	}

	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("clé déroulée incohérente: obtenu %x, attendu %x", unwrapped, dek)
	}

	// Altération de la clé encapsulée => doit échouer
	tamperedEncap := make([]byte, len(wrapped.EncapsulatedKey))
	copy(tamperedEncap, wrapped.EncapsulatedKey)
	tamperedEncap[0] ^= 0xFF
	if _, err := crypto.UnwrapKey(ctx, engine, tamperedEncap, wrapped.Nonce, wrapped.Data); err == nil {
		t.Fatal("UnwrapKey avec encapKey altérée aurait dû échouer")
	}
}

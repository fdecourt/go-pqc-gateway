package infisical_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/infisical"
)

type fakeInfisicalServer struct {
	mu      sync.Mutex
	secrets map[string]string
}

func newFakeInfisicalServer() (*fakeInfisicalServer, *httptest.Server) {
	fake := &fakeInfisicalServer{
		secrets: make(map[string]string),
	}

	mux := http.NewServeMux()

	// Universal Auth Login
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"accessToken": "mock-token-xyz",
			"expiresIn":   3600,
		})
	})

	// Secrets Raw v3
	mux.HandleFunc("/api/v3/secrets/raw/", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()

		secretName := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
		if idx := strings.Index(secretName, "?"); idx != -1 {
			secretName = secretName[:idx]
		}

		switch r.Method {
		case http.MethodGet:
			val, ok := fake.secrets[secretName]
			if !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": map[string]string{
					"secretKey":   secretName,
					"secretValue": val,
				},
			})

		case http.MethodPost:
			var req struct {
				SecretValue string `json:"secretValue"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			fake.secrets[secretName] = req.SecretValue
			w.WriteHeader(http.StatusOK)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewServer(mux)
	return fake, server
}

func testConfig(serverURL string) *config.Config {
	return &config.Config{
		InfisicalURL:               serverURL,
		InfisicalClientID:          "client-id",
		InfisicalClientSecret:      "client-secret",
		InfisicalProjectID:         "project-123",
		InfisicalEnv:               "test",
		InfisicalSecretPubKeyName:  "PQ_KEM_PUBLIC_KEY",
		InfisicalSecretPrivKeyName: "PQ_KEM_PRIVATE_KEY",
		InfisicalSecretBundleName:  "PQ_KEM_KEYPAIR",
		Algorithm:                  "ML-KEM-768",
	}
}

// TestFetchKeys_CleanVault vérifie qu'un coffre vide retourne ErrSecretNotFound
func TestFetchKeys_CleanVault(t *testing.T) {
	_, server := newFakeInfisicalServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	client := infisical.NewClient(cfg)

	_, _, err := client.FetchKeys(context.Background())
	if err == nil {
		t.Fatal("attendu ErrSecretNotFound sur coffre vierge")
	}
	if !errors.Is(err, infisical.ErrSecretNotFound) {
		t.Fatalf("erreur inattendue: %v", err)
	}
}

// TestStoreAndFetch_AtomicBundle vérifie le stockage et relecture du bundle atomique avec checksum
func TestStoreAndFetch_AtomicBundle(t *testing.T) {
	fake, server := newFakeInfisicalServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	client := infisical.NewClient(cfg)

	origPK := []byte("fake-public-key-data-123456789012")
	origSK := []byte("fake-private-key-data-098765432109")

	if err := client.StoreKeys(context.Background(), origPK, origSK); err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	// Vérifier que le bundle atomique a bien été créé
	fake.mu.Lock()
	bundleRaw, bundleExists := fake.secrets["PQ_KEM_KEYPAIR"]
	fake.mu.Unlock()

	if !bundleExists {
		t.Fatal("le bundle atomique PQ_KEM_KEYPAIR n'a pas été créé")
	}

	var bundle infisical.KeypairBundle
	if err := json.Unmarshal([]byte(bundleRaw), &bundle); err != nil {
		t.Fatalf("bundle JSON non valide: %v", err)
	}
	if bundle.FormatVersion != 1 {
		t.Errorf("FormatVersion attendu 1, obtenu %d", bundle.FormatVersion)
	}

	// Relecture via FetchKeys
	readPK, readSK, err := client.FetchKeys(context.Background())
	if err != nil {
		t.Fatalf("FetchKeys failed: %v", err)
	}
	if string(readPK) != string(origPK) {
		t.Errorf("PK mismatch: got %s, want %s", readPK, origPK)
	}
	if string(readSK) != string(origSK) {
		t.Errorf("SK mismatch: got %s, want %s", readSK, origSK)
	}
}

// TestFetchKeys_CorruptedBundleChecksum vérifie le rejet fatal en cas de corruption de données
func TestFetchKeys_CorruptedBundleChecksum(t *testing.T) {
	fake, server := newFakeInfisicalServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	client := infisical.NewClient(cfg)

	bundle := infisical.KeypairBundle{
		FormatVersion: 1,
		Algorithm:     "ML-KEM-768",
		PublicKey:     base64.StdEncoding.EncodeToString([]byte("pk-data")),
		PrivateKey:    base64.StdEncoding.EncodeToString([]byte("sk-data")),
		Checksum:      "invalid-falsified-checksum",
	}
	bundleBytes, _ := json.Marshal(bundle)

	fake.mu.Lock()
	fake.secrets["PQ_KEM_KEYPAIR"] = string(bundleBytes)
	fake.mu.Unlock()

	_, _, err := client.FetchKeys(context.Background())
	if err == nil {
		t.Fatal("FetchKeys aurait dû rejeter un checksum falsifié")
	}
	if !errors.Is(err, infisical.ErrCorruptedBundle) {
		t.Fatalf("attendu ErrCorruptedBundle, obtenu: %v", err)
	}
}

// TestFetchKeys_PartialStateRejection vérifie la détection stricte des 4 états
// en cas d'absence de bundle atomique (migration / legacy)
func TestFetchKeys_PartialStateRejection(t *testing.T) {
	fake, server := newFakeInfisicalServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	client := infisical.NewClient(cfg)

	// Cas 1 : PK seule présente (SK absente)
	fake.mu.Lock()
	fake.secrets["PQ_KEM_PUBLIC_KEY"] = base64.StdEncoding.EncodeToString([]byte("orphan-pk"))
	delete(fake.secrets, "PQ_KEM_PRIVATE_KEY")
	delete(fake.secrets, "PQ_KEM_KEYPAIR")
	fake.mu.Unlock()

	_, _, err := client.FetchKeys(context.Background())
	if err == nil {
		t.Fatal("attendu rejet d'état partiel (PK seule)")
	}
	if !errors.Is(err, infisical.ErrPartialKeypair) {
		t.Fatalf("attendu ErrPartialKeypair, obtenu: %v", err)
	}

	// Cas 2 : SK seule présente (PK absente)
	fake.mu.Lock()
	delete(fake.secrets, "PQ_KEM_PUBLIC_KEY")
	fake.secrets["PQ_KEM_PRIVATE_KEY"] = base64.StdEncoding.EncodeToString([]byte("orphan-sk"))
	fake.mu.Unlock()

	_, _, err = client.FetchKeys(context.Background())
	if err == nil {
		t.Fatal("attendu rejet d'état partiel (SK seule)")
	}
	if !errors.Is(err, infisical.ErrPartialKeypair) {
		t.Fatalf("attendu ErrPartialKeypair, obtenu: %v", err)
	}

	// Cas 3 : Les deux clés legacy sont présentes -> succès
	fake.mu.Lock()
	fake.secrets["PQ_KEM_PUBLIC_KEY"] = base64.StdEncoding.EncodeToString([]byte("valid-pk"))
	fake.secrets["PQ_KEM_PRIVATE_KEY"] = base64.StdEncoding.EncodeToString([]byte("valid-sk"))
	fake.mu.Unlock()

	pk, sk, err := client.FetchKeys(context.Background())
	if err != nil {
		t.Fatalf("chargement legacy complet échoué: %v", err)
	}
	if string(pk) != "valid-pk" || string(sk) != "valid-sk" {
		t.Fatalf("clés récupérées incorrectes: pk=%s, sk=%s", pk, sk)
	}
}

// TestFetchKeys_AuthFailure vérifie la propagation d'une erreur d'auth (pas de fallback silencieux)
func TestFetchKeys_AuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	client := infisical.NewClient(cfg)

	_, _, err := client.FetchKeys(context.Background())
	if err == nil {
		t.Fatal("attendu erreur d'authentification")
	}
	if !errors.Is(err, infisical.ErrAuthFailed) {
		t.Fatalf("attendu ErrAuthFailed, obtenu: %v", err)
	}
}

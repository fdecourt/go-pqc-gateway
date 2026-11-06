package infisical_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"pq-crypto-service/internal/infisical"
	"pq-crypto-service/internal/keystore"
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
		_ = json.NewEncoder(w).Encode(map[string]any{
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
			_ = json.NewEncoder(w).Encode(map[string]any{
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

func testConfig(serverURL string) infisical.Options {
	return infisical.Options{
		URL:          serverURL,
		ClientID:     "client-id",
		ClientSecret: []byte("client-secret"),
		ProjectID:    "project-123",
		Environment:  "test",
		BundleName:   "PQ_KEM_KEYPAIR",
		Algorithm:    "ML-KEM-768",

		LegacyPubKeyName:  "PQ_KEM_PUBLIC_KEY",
		LegacyPrivKeyName: "PQ_KEM_PRIVATE_KEY",
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

// TestFetchKeys_LegacyLayoutBlocksBootstrap vérifie que l'ancien format scindé (deux secrets)
// n'est plus lu, et que sa présence, même partielle, interdit la génération d'une paire neuve.
func TestFetchKeys_LegacyLayoutBlocksBootstrap(t *testing.T) {
	for _, present := range [][]string{
		{"PQ_KEM_PUBLIC_KEY"},
		{"PQ_KEM_PRIVATE_KEY"},
		{"PQ_KEM_PUBLIC_KEY", "PQ_KEM_PRIVATE_KEY"},
	} {
		fake, server := newFakeInfisicalServer()
		fake.mu.Lock()
		for _, name := range present {
			fake.secrets[name] = base64.StdEncoding.EncodeToString([]byte("legacy"))
		}
		fake.mu.Unlock()

		_, _, err := infisical.NewClient(testConfig(server.URL)).FetchKeys(context.Background())
		server.Close()
		if !errors.Is(err, infisical.ErrLegacyLayout) || !errors.Is(err, keystore.ErrBootstrapForbidden) {
			t.Fatalf("%v présents : attendu ErrLegacyLayout, obtenu %v", present, err)
		}
	}
}

// TestStoreKeys_RedirectsAreRefused vérifie qu'aucune redirection n'est suivie : le corps,
// qui contient la clé privée, ne doit jamais partir vers un autre hôte.
func TestStoreKeys_RedirectsAreRefused(t *testing.T) {
	leaked := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer evil.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"accessToken":"t","expiresIn":3600}`))
	})
	mux.HandleFunc("/api/v3/secrets/raw/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusTemporaryRedirect)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	err := infisical.NewClient(testConfig(server.URL)).StoreKeys(context.Background(), []byte("pk"), []byte("sk"))
	if err == nil {
		t.Fatal("une redirection doit faire échouer StoreKeys")
	}
	if leaked {
		t.Fatal("le corps (clé privée) a été renvoyé vers l'hôte de redirection")
	}
}

// TestSecretNames_AreValidated vérifie qu'un nom de secret ne peut pas altérer le chemin de l'URL.
func TestSecretNames_AreValidated(t *testing.T) {
	_, server := newFakeInfisicalServer()
	defer server.Close()
	opts := testConfig(server.URL)
	opts.BundleName = "../../v1/other"
	if _, _, err := infisical.NewClient(opts).FetchKeys(context.Background()); err == nil || !strings.Contains(err.Error(), "invalide") {
		t.Fatalf("nom de secret avec ../ accepté: %v", err)
	}
}

// TestResponses_AreBounded vérifie qu'une instance Infisical hostile ou défaillante
// ne peut ni saturer la mémoire ni polluer les logs avec un corps de réponse démesuré.
func TestResponses_AreBounded(t *testing.T) {
	huge := strings.Repeat("A", 8<<20)

	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, huge, http.StatusUnauthorized)
	}))
	defer errServer.Close()
	_, _, err := infisical.NewClient(testConfig(errServer.URL)).FetchKeys(context.Background())
	if err == nil || len(err.Error()) > 8<<10 {
		t.Fatalf("corps d'erreur non borné (%d octets dans le message)", len(err.Error()))
	}

	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"` + huge + `","expiresIn":3600}`))
	}))
	defer okServer.Close()
	if _, _, err := infisical.NewClient(testConfig(okServer.URL)).FetchKeys(context.Background()); err == nil {
		t.Fatal("une réponse de 8 Mo aurait dû être refusée au décodage")
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

// TestClient_CloseWipesSecret vérifie que Close efface le client_secret et rend le client inutilisable.
func TestClient_CloseWipesSecret(t *testing.T) {
	_, server := newFakeInfisicalServer()
	defer server.Close()
	secret := []byte("client-secret")
	opts := testConfig(server.URL)
	opts.ClientSecret = secret
	c := infisical.NewClient(opts)
	for i := range secret {
		secret[i] = 0 // l'appelant efface sa copie : le client doit avoir la sienne
	}
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, infisical.ErrSecretNotFound) {
		t.Fatalf("le client doit fonctionner avec sa propre copie du secret: %v", err)
	}
	c.Close()
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, infisical.ErrAuthFailed) {
		t.Fatalf("après Close, l'authentification doit échouer: %v", err)
	}
}

// TestClient_RequiresTLS13AndPinnedCA vérifie que le transport refuse TLS 1.2 et une CA inconnue.
func TestClient_RequiresTLS13AndPinnedCA(t *testing.T) {
	tls12 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tls12.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	tls12.StartTLS()
	defer tls12.Close()
	opts := testConfig(tls12.URL)
	opts.CAFile = writeTempPEM(t, tls12.Certificate())
	if _, _, err := infisical.NewClient(opts).FetchKeys(context.Background()); err == nil || errors.Is(err, infisical.ErrSecretNotFound) {
		t.Fatalf("une instance limitée à TLS 1.2 doit être refusée: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"accessToken":"t","expiresIn":3600}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	opts = testConfig(srv.URL)
	if _, _, err := infisical.NewClient(opts).FetchKeys(context.Background()); err == nil || errors.Is(err, infisical.ErrSecretNotFound) {
		t.Fatalf("un certificat inconnu de la CA système doit être refusé: %v", err)
	}
	opts.CAFile = writeTempPEM(t, srv.Certificate())
	if _, _, err := infisical.NewClient(opts).FetchKeys(context.Background()); !errors.Is(err, infisical.ErrSecretNotFound) {
		t.Fatalf("avec INFISICAL_CA_FILE, la connexion doit aboutir (coffre vide attendu): %v", err)
	}
}

func writeTempPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

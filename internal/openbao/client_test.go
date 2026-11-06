package openbao_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"pq-crypto-service/internal/crypto"
	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/openbao"
)

const (
	testToken   = "s.test-token"
	appRoleID   = "role-123"
	appSecretID = "secret-456"
)

// fakeBao imite le moteur KV v2 d'OpenBao : versions, check-and-set, suppression douce,
// métadonnées, et authentification par jeton ou AppRole.
type fakeBao struct {
	mu          sync.Mutex
	versions    []map[string]any // index = version - 1
	deleted     map[int]bool
	metaWritten bool
	casRequired bool
	namespaces  []string
	logins      int
	// canUpdate imite une politique qui accorde « update » sur la paire. Faux par défaut :
	// politique minimale (create, read), sous laquelle OpenBao refuse toute écriture de
	// données dès que le secret existe (métadonnées comprises).
	canUpdate bool
	revoked   bool
}

func newFakeBao(t *testing.T) (*fakeBao, *httptest.Server) {
	t.Helper()
	f := &fakeBao{deleted: map[int]bool{}}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ RoleID, SecretID string }
		var raw map[string]string
		_ = json.NewDecoder(r.Body).Decode(&raw)
		req.RoleID, req.SecretID = raw["role_id"], raw["secret_id"]
		if req.RoleID != appRoleID || req.SecretID != appSecretID {
			http.Error(w, `{"errors":["invalid role or secret ID"]}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.logins++
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": testToken}})
	})

	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			revoked := f.revoked
			f.mu.Unlock()
			if r.Header.Get("X-Vault-Token") != testToken || revoked {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			f.mu.Lock()
			f.namespaces = append(f.namespaces, r.Header.Get("X-Vault-Namespace"))
			f.mu.Unlock()
			h(w, r)
		}
	}

	mux.HandleFunc("/v1/auth/token/revoke-self", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("/v1/secret/data/pq-crypto-service/keypair", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			if len(f.versions) == 0 {
				http.Error(w, `{"errors":[]}`, http.StatusNotFound)
				return
			}
			v := len(f.versions)
			md := map[string]any{"version": v, "deletion_time": "", "destroyed": false}
			if f.deleted[v] {
				md["deletion_time"] = "2026-11-06T10:00:00Z"
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": nil, "metadata": md}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": f.versions[v-1], "metadata": md}})
		case http.MethodPost:
			var req struct {
				Options *struct {
					CAS *int `json:"cas"`
				} `json:"options"`
				Data map[string]any `json:"data"`
			}
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, `{"errors":["bad json"]}`, http.StatusBadRequest)
				return
			}
			if (f.metaWritten || len(f.versions) > 0) && !f.canUpdate {
				http.Error(w, `{"errors":["1 error occurred:
	* permission denied

"]}`, http.StatusForbidden)
				return
			}
			hasCAS := req.Options != nil && req.Options.CAS != nil
			if f.casRequired && !hasCAS {
				http.Error(w, `{"errors":["check-and-set parameter required for this call"]}`, http.StatusBadRequest)
				return
			}
			if hasCAS && *req.Options.CAS != len(f.versions) {
				http.Error(w, `{"errors":["check-and-set parameter did not match the current version"]}`, http.StatusBadRequest)
				return
			}
			f.versions = append(f.versions, req.Data)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": len(f.versions)}})
		}
	}))

	mux.HandleFunc("/v1/secret/metadata/pq-crypto-service/keypair", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			if !f.metaWritten && len(f.versions) == 0 {
				http.Error(w, `{"errors":[]}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"current_version": len(f.versions)}})
		case http.MethodPost:
			var md map[string]any
			_ = json.NewDecoder(r.Body).Decode(&md)
			f.metaWritten = true
			f.casRequired, _ = md["cas_required"].(bool)
			w.WriteHeader(http.StatusNoContent)
		}
	}))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func tokenOptions(addr string) openbao.Options {
	return openbao.Options{Addr: addr, AuthMethod: openbao.AuthToken, Token: []byte(testToken), Algorithm: "ML-KEM-768"}
}

func TestFetchKeys_NeverWritten(t *testing.T) {
	_, srv := newFakeBao(t)
	c := openbao.NewClient(tokenOptions(srv.URL))
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, keystore.ErrSecretNotFound) {
		t.Fatalf("coffre vierge : ErrSecretNotFound attendu, obtenu %v", err)
	}
}

// TestStoreAndFetch_RoundTrip vérifie l'aller-retour et la pose des métadonnées protectrices.
func TestStoreAndFetch_RoundTrip(t *testing.T) {
	f, srv := newFakeBao(t)
	c := openbao.NewClient(tokenOptions(srv.URL))
	pk, sk, _ := crypto.GenerateKeyPair("ML-KEM-768")
	if err := c.StoreKeys(context.Background(), pk, sk); err != nil {
		t.Fatal(err)
	}
	gotPK, gotSK, err := c.FetchKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPK) != string(pk) || string(gotSK) != string(sk) {
		t.Fatal("paire relue différente de la paire écrite")
	}
	if !f.casRequired {
		t.Fatal("les métadonnées doivent imposer le check-and-set (cas_required)")
	}
	if fv := f.versions[0]["format_version"]; fv != float64(keystore.BundleFormatVersion) {
		t.Fatalf("bundle stocké au format %v, attendu %d (format commun à tous les coffres)", fv, keystore.BundleFormatVersion)
	}
}

// TestStoreKeys_NeverOverwrites vérifie qu'une seconde écriture est refusée et que la
// première paire reste intacte : aucune génération ne peut remplacer une paire existante.
func TestStoreKeys_NeverOverwrites(t *testing.T) {
	f, srv := newFakeBao(t)
	f.canUpdate = true // même un jeton qui peut écrire ne remplace pas la paire : cas=0
	c := openbao.NewClient(tokenOptions(srv.URL))
	pk1, sk1, _ := crypto.GenerateKeyPair("ML-KEM-768")
	pk2, sk2, _ := crypto.GenerateKeyPair("ML-KEM-768")
	if err := c.StoreKeys(context.Background(), pk1, sk1); err != nil {
		t.Fatal(err)
	}
	if err := c.StoreKeys(context.Background(), pk2, sk2); !errors.Is(err, openbao.ErrWriteConflict) {
		t.Fatalf("seconde écriture : ErrWriteConflict attendu, obtenu %v", err)
	}
	gotPK, _, err := c.FetchKeys(context.Background())
	if err != nil || string(gotPK) != string(pk1) {
		t.Fatalf("la première paire doit rester intacte (err=%v)", err)
	}
}

// TestFetchKeys_DeletedVersionBlocksBootstrap vérifie qu'une paire supprimée bloque le
// démarrage au lieu de laisser générer une nouvelle paire.
func TestFetchKeys_DeletedVersionBlocksBootstrap(t *testing.T) {
	f, srv := newFakeBao(t)
	c := openbao.NewClient(tokenOptions(srv.URL))
	pk, sk, _ := crypto.GenerateKeyPair("ML-KEM-768")
	if err := c.StoreKeys(context.Background(), pk, sk); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.deleted[1] = true
	f.mu.Unlock()

	_, _, err := c.FetchKeys(context.Background())
	if !errors.Is(err, keystore.ErrBootstrapForbidden) {
		t.Fatalf("paire supprimée : ErrBootstrapForbidden attendu, obtenu %v", err)
	}
	if _, err := crypto.BuildEngine(context.Background(), crypto.EngineOptions{Algorithm: "ML-KEM-768"}, c); err == nil {
		t.Fatal("le moteur ne doit pas démarrer sur une paire supprimée")
	}
	if len(f.versions) != 1 {
		t.Fatal("aucune nouvelle paire ne doit avoir été écrite")
	}
}

func TestFetchKeys_CorruptedBundle(t *testing.T) {
	f, srv := newFakeBao(t)
	c := openbao.NewClient(tokenOptions(srv.URL))
	pk, sk, _ := crypto.GenerateKeyPair("ML-KEM-768")
	if err := c.StoreKeys(context.Background(), pk, sk); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.versions[0]["checksum"] = strings.Repeat("0", 64)
	f.mu.Unlock()
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, keystore.ErrCorruptedBundle) {
		t.Fatalf("ErrCorruptedBundle attendu, obtenu %v", err)
	}
}

// TestAppRole_LoginOnceAndNamespace vérifie la connexion AppRole (une seule fois) et l'envoi
// de l'espace de noms.
func TestAppRole_LoginOnceAndNamespace(t *testing.T) {
	f, srv := newFakeBao(t)
	c := openbao.NewClient(openbao.Options{
		Addr: srv.URL, AuthMethod: openbao.AuthAppRole, RoleID: appRoleID,
		SecretID: []byte(appSecretID), Namespace: "team-a", Algorithm: "ML-KEM-768",
	})
	pk, sk, _ := crypto.GenerateKeyPair("ML-KEM-768")
	if err := c.StoreKeys(context.Background(), pk, sk); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.FetchKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.logins != 1 {
		t.Fatalf("connexions AppRole : %d, attendu 1", f.logins)
	}
	for _, ns := range f.namespaces {
		if ns != "team-a" {
			t.Fatalf("espace de noms envoyé : %q", ns)
		}
	}
}

func TestAuthFailure_AndClose(t *testing.T) {
	_, srv := newFakeBao(t)
	bad := openbao.NewClient(openbao.Options{Addr: srv.URL, AuthMethod: openbao.AuthAppRole, RoleID: appRoleID, SecretID: []byte("faux")})
	if _, _, err := bad.FetchKeys(context.Background()); !errors.Is(err, openbao.ErrAuthFailed) {
		t.Fatalf("ErrAuthFailed attendu, obtenu %v", err)
	}

	secret := []byte(appSecretID)
	c := openbao.NewClient(openbao.Options{Addr: srv.URL, AuthMethod: openbao.AuthAppRole, RoleID: appRoleID, SecretID: secret})
	clear(secret) // l'appelant efface sa copie : le client garde la sienne
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, keystore.ErrSecretNotFound) {
		t.Fatalf("le client doit fonctionner avec sa propre copie : %v", err)
	}
	c.Close()
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, openbao.ErrAuthFailed) {
		t.Fatalf("après Close, l'authentification doit échouer : %v", err)
	}
}

// TestRedirectsAreRefused vérifie que la clé privée n'est jamais renvoyée vers un autre hôte.
func TestRedirectsAreRefused(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer evil.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	c := openbao.NewClient(tokenOptions(redirector.URL))
	pk, sk, _ := crypto.GenerateKeyPair("ML-KEM-768")
	if err := c.StoreKeys(context.Background(), pk, sk); err == nil {
		t.Fatal("une redirection doit faire échouer l'écriture")
	}
	if leaked {
		t.Fatal("la requête a suivi la redirection vers un autre hôte")
	}
}

func TestOptionsValidate(t *testing.T) {
	ok := openbao.Options{Addr: "https://bao:8200", AuthMethod: openbao.AuthToken, Token: []byte("t")}
	for _, tc := range []struct {
		name       string
		mutate     func(*openbao.Options)
		production bool
		wantErr    bool
	}{
		{"https en production", func(*openbao.Options) {}, true, false},
		{"http refusé en production", func(o *openbao.Options) { o.Addr = "http://bao:8200" }, true, true},
		{"http toléré hors production", func(o *openbao.Options) { o.Addr = "http://bao:8200" }, false, false},
		{"jeton manquant", func(o *openbao.Options) { o.Token = nil }, false, true},
		{"approle incomplet", func(o *openbao.Options) { o.AuthMethod = openbao.AuthAppRole; o.RoleID = "r" }, false, true},
		{"méthode inconnue", func(o *openbao.Options) { o.AuthMethod = "ldap" }, false, true},
		{"chemin avec ..", func(o *openbao.Options) { o.SecretPath = "a/../b" }, false, true},
		{"montage avec espace", func(o *openbao.Options) { o.KVMount = "kv v2" }, false, true},
		{"espace de noms imbriqué", func(o *openbao.Options) { o.Namespace = "org/team" }, false, false},
	} {
		o := ok
		tc.mutate(&o)
		if err := o.Validate(tc.production); (err != nil) != tc.wantErr {
			t.Errorf("%s : erreur = %v, attendu erreur = %v", tc.name, err, tc.wantErr)
		}
	}
}

// TestRegistered vérifie que le coffre est sélectionnable par KEYSTORE=openbao.
func TestRegistered(t *testing.T) {
	b, err := keystore.Lookup("OpenBao")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.SecretVars) != 2 {
		t.Fatalf("variables secrètes déclarées : %v", b.SecretVars)
	}
}

// TestClose_RevokesAppRoleTokenOnly vérifie que Close révoque le jeton obtenu par AppRole (sa
// valeur a transité par des chaînes Go non effaçables), mais pas un jeton statique, qui
// resservira au prochain démarrage.
func TestClose_RevokesAppRoleTokenOnly(t *testing.T) {
	f, srv := newFakeBao(t)
	c := openbao.NewClient(openbao.Options{Addr: srv.URL, AuthMethod: openbao.AuthAppRole, RoleID: appRoleID, SecretID: []byte(appSecretID)})
	if _, _, err := c.FetchKeys(context.Background()); !errors.Is(err, keystore.ErrSecretNotFound) {
		t.Fatal(err)
	}
	c.Close()
	if !f.revoked {
		t.Fatal("le jeton AppRole doit être révoqué à la fermeture")
	}

	f2, srv2 := newFakeBao(t)
	static := openbao.NewClient(tokenOptions(srv2.URL))
	if _, _, err := static.FetchKeys(context.Background()); !errors.Is(err, keystore.ErrSecretNotFound) {
		t.Fatal(err)
	}
	static.Close()
	if f2.revoked {
		t.Fatal("un jeton statique (OPENBAO_TOKEN) ne doit pas être révoqué")
	}
}

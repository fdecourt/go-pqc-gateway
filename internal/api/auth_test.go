package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/credential"
	"pq-crypto-service/internal/crypto"
)

const (
	tokenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tokenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func authRouter(t *testing.T, bind bool) http.Handler {
	t.Helper()
	engine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Port: 8080, MaxPayloadBytes: 1 << 20, BindClientIdentity: bind,
		AuthTokens: []credential.Token{
			{Name: "app-a", Hash: credential.HashToken([]byte(tokenA))},
			{Name: "app-b", Hash: credential.HashToken([]byte(tokenB))},
		}}
	r := NewRouter(cfg, engine)
	t.Cleanup(r.Close)
	return r
}

func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestTokenAuth(t *testing.T) {
	h := authRouter(t, false)
	if rr := do(h, http.MethodGet, "/public-key", "", ""); rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("sans jeton: %d", rr.Code)
	}
	if rr := do(h, http.MethodGet, "/public-key", "cccccccccccccccccccccccccccccccccccccccc", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("mauvais jeton: %d", rr.Code)
	}
	if rr := do(h, http.MethodGet, "/public-key", tokenA, ""); rr.Code != http.StatusOK {
		t.Fatalf("bon jeton: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(h, http.MethodGet, "/metrics", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics sans jeton: %d", rr.Code)
	}
	// /health reste joignable, mais minimal.
	rr := do(h, http.MethodGet, "/health", "", "")
	var health map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &health)
	if rr.Code != http.StatusOK || health["algorithm"] != nil {
		t.Fatalf("/health sans jeton doit être minimal: %d %v", rr.Code, health)
	}
	// « bearer » insensible à la casse, espaces tolérés.
	req := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	req.Header.Set("Authorization", "bearer  "+tokenA+" ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("schéma en minuscules: %d", rec.Code)
	}
}

func TestBindClientIdentity_IsolatesTenants(t *testing.T) {
	h := authRouter(t, true)
	enc := do(h, http.MethodPost, "/encrypt", tokenA, `{"plaintext":"secret de A","context":"dossier=1"}`)
	if enc.Code != http.StatusOK {
		t.Fatalf("/encrypt: %d %s", enc.Code, enc.Body.String())
	}
	envelope := enc.Body.String()
	withCtx := strings.Replace(envelope, `{"algorithm"`, `{"context":"dossier=1","algorithm"`, 1)

	if rr := do(h, http.MethodPost, "/decrypt", tokenA, withCtx); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "secret de A") {
		t.Fatalf("le client A doit pouvoir rouvrir son enveloppe: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(h, http.MethodPost, "/decrypt", tokenB, withCtx); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("le client B ne doit pas pouvoir ouvrir l'enveloppe de A: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(h, http.MethodPost, "/decrypt", tokenA, envelope); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sans le contexte client, l'ouverture doit échouer: %d", rr.Code)
	}
}

func TestBindClientIdentity_RequiresIdentity(t *testing.T) {
	engine, _ := crypto.NewEngineForSuite("ML-KEM-768")
	r := NewRouter(&config.Config{Port: 8080, MaxPayloadBytes: 1 << 20, BindClientIdentity: true}, engine)
	defer r.Close()
	if rr := do(r, http.MethodPost, "/encrypt", "", `{"plaintext":"x"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("sans identité: %d", rr.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/encrypt", strings.NewReader(`{"plaintext":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ContextWithPeerUID(req.Context(), 10001))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("avec l'UID du pair comme identité: %d %s", rr.Code, rr.Body.String())
	}
}

func TestBoundContext_IsUnambiguous(t *testing.T) {
	a := BoundContext("app-a", []byte("x"))
	b := BoundContext("app-a\x00x", nil)
	if bytes.Equal(a, b) {
		t.Fatal("deux couples (identité, contexte) distincts ne doivent pas donner le même contexte lié")
	}
	if !printableIdentity("app-a") || printableIdentity("app\x00a") || printableIdentity("app a") {
		t.Fatal("une identité doit être imprimable, sans espace ni contrôle")
	}
}

func TestIdentityKeyedSourceLimit(t *testing.T) {
	engine, _ := crypto.NewEngineForSuite("ML-KEM-768")
	cfg := &config.Config{Port: 8080, MaxPayloadBytes: 1 << 20, RateLimitRPS: 1, RateLimitBurst: 2,
		AuthTokens: []credential.Token{{Name: "app-a", Hash: credential.HashToken([]byte(tokenA))}, {Name: "app-b", Hash: credential.HashToken([]byte(tokenB))}}}
	r := NewRouter(cfg, engine)
	defer r.Close()
	for i := 0; i < 2; i++ {
		if rr := do(r, http.MethodGet, "/public-key", tokenA, ""); rr.Code != http.StatusOK {
			t.Fatalf("A requête %d: %d", i, rr.Code)
		}
	}
	if rr := do(r, http.MethodGet, "/public-key", tokenA, ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("A au-delà de la rafale: %d", rr.Code)
	}
	// Même adresse réseau, autre identité : quota distinct.
	if rr := do(r, http.MethodGet, "/public-key", tokenB, ""); rr.Code != http.StatusOK {
		t.Fatalf("B doit avoir son propre quota: %d", rr.Code)
	}
}

func TestContentEncodingRejected(t *testing.T) {
	h := authRouter(t, false)
	req := httptest.NewRequest(http.MethodPost, "/encrypt", strings.NewReader(`{"plaintext":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+tokenA)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Content-Encoding: gzip doit être refusé: %d", rr.Code)
	}
}

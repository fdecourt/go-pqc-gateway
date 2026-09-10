package api_test

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

func TestRouterAssembly_200And429(t *testing.T) {
	// Capturer les logs émis par LoggerMiddleware
	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOutput)

	cfg := &config.Config{
		RateLimitRPS:         1,
		RateLimitBurst:       1,
		AccessLog:            true,
		MaxPayloadBytes:      1024 * 1024,
		AllowLegacyEnvelopes: false,
	}

	engine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatalf("échec d'instanciation du moteur: %v", err)
	}

	router := api.NewRouter(cfg, engine)
	defer router.Close()

	// 1. Requête 200 OK avec génération automatique de CID
	req200 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req200.RemoteAddr = "10.0.0.1:4567"
	rr200 := httptest.NewRecorder()

	router.ServeHTTP(rr200, req200)

	if rr200.Code != http.StatusOK {
		t.Fatalf("attendu statut 200, obtenu %d", rr200.Code)
	}
	cid200 := rr200.Header().Get("X-Correlation-ID")
	if cid200 == "" {
		t.Errorf("X-Correlation-ID manquant sur réponse 200")
	}
	if ctOpt := rr200.Header().Get("X-Content-Type-Options"); ctOpt != "nosniff" {
		t.Errorf("attendu X-Content-Type-Options 'nosniff', obtenu %q", ctOpt)
	}
	if csp := rr200.Header().Get("Content-Security-Policy"); csp == "" {
		t.Errorf("Content-Security-Policy manquant sur réponse 200")
	}

	// 2. Requête 429 Too Many Requests (même IP, dépasse le burst de 1)
	req429 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req429.RemoteAddr = "10.0.0.1:4567"
	req429.Header.Set("X-Correlation-ID", "custom-audit-cid-429")
	rr429 := httptest.NewRecorder()

	router.ServeHTTP(rr429, req429)

	if rr429.Code != http.StatusTooManyRequests {
		t.Fatalf("attendu statut 429, obtenu %d", rr429.Code)
	}
	cid429 := rr429.Header().Get("X-Correlation-ID")
	if cid429 != "custom-audit-cid-429" {
		t.Errorf("attendu X-Correlation-ID 'custom-audit-cid-429', obtenu %q", cid429)
	}
	if ctOpt := rr429.Header().Get("X-Content-Type-Options"); ctOpt != "nosniff" {
		t.Errorf("attendu X-Content-Type-Options 'nosniff' sur 429, obtenu %q", ctOpt)
	}
	if csp := rr429.Header().Get("Content-Security-Policy"); csp == "" {
		t.Errorf("Content-Security-Policy manquant sur réponse 429")
	}

	// 3. Vérification des logs d'accès structurés (slog)
	logOutput := logBuf.String()
	if strings.Contains(logOutput, `correlation_id=""`) {
		t.Errorf("cid vide trouvé dans la journalisation: %s", logOutput)
	}
	if !strings.Contains(logOutput, "correlation_id="+cid200) {
		t.Errorf("log ne contient pas le cid généré %q: %s", cid200, logOutput)
	}
	if !strings.Contains(logOutput, "correlation_id=custom-audit-cid-429") {
		t.Errorf("log ne contient pas le cid personnalisé pour 429: %s", logOutput)
	}
	if !strings.Contains(logOutput, "status=429") {
		t.Errorf("log ne trace pas le statut HTTP 429: %s", logOutput)
	}
}

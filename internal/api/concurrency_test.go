package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingHandler retient chaque requête /encrypt jusqu'à la fermeture de release.
func blockingHandler() (h http.Handler, entered chan struct{}, release chan struct{}) {
	entered, release = make(chan struct{}, 16), make(chan struct{})
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/encrypt" {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	})
	return h, entered, release
}

func requestFrom(ip, path string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.RemoteAddr = ip + ":40000"
	return r
}

// TestConcurrencyLimit_Global vérifie qu'au-delà du plafond une requête obtient 503 +
// Retry-After après une attente bornée, que /health et /metrics restent servis, et que
// le créneau est rendu à la fin de la requête.
func TestConcurrencyLimit_Global(t *testing.T) {
	slow, entered, release := blockingHandler()
	m := NewMetrics("test", "algo", []string{"/encrypt", "/health", metricsPath})
	handler := ConcurrencyLimitMiddleware(1, NewClientIPResolver(nil), m)(slow)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handler.ServeHTTP(httptest.NewRecorder(), requestFrom("10.0.0.1", "/encrypt"))
	}()
	<-entered // le seul créneau est occupé par 10.0.0.1

	start := time.Now()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestFrom("10.0.0.2", "/encrypt"))
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("requête excédentaire: %d (Retry-After=%q), attendu 503", rr.Code, rr.Header().Get("Retry-After"))
	}
	if waited := time.Since(start); waited < concurrencyWait/2 {
		t.Fatalf("rejet global sans attente bornée (%v)", waited)
	}
	if !strings.Contains(m.Render(), "pqc_overloaded_total 1") {
		t.Fatal("rejet non comptabilisé dans pqc_overloaded_total")
	}

	for _, path := range []string{"/health", metricsPath} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, requestFrom("10.0.0.2", path))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s bloqué par le plafond de concurrence: %d", path, rr.Code)
		}
	}

	close(release)
	wg.Wait()
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, requestFrom("10.0.0.2", "/encrypt"))
	if rr.Code != http.StatusOK {
		t.Fatalf("créneau non rendu après la fin de la requête: %d", rr.Code)
	}
}

// TestConcurrencyLimit_PerIP vérifie qu'une source unique (client lent, par exemple) ne peut
// occuper qu'un quart des créneaux, les autres restant disponibles pour les autres sources.
func TestConcurrencyLimit_PerIP(t *testing.T) {
	slow, entered, release := blockingHandler()
	handler := ConcurrencyLimitMiddleware(8, NewClientIPResolver(nil), nil)(slow) // 2 créneaux par IP

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.ServeHTTP(httptest.NewRecorder(), requestFrom("10.0.0.1", "/encrypt"))
		}()
		<-entered
	}

	start := time.Now()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestFrom("10.0.0.1", "/encrypt"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("3e requête simultanée d'une même IP: %d, attendu 503", rr.Code)
	}
	if time.Since(start) > concurrencyWait/2 {
		t.Fatal("le dépassement de quota par IP doit être refusé sans attendre")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, requestFrom("10.0.0.2", "/encrypt"))
		if rr.Code != http.StatusOK {
			t.Errorf("autre IP bloquée alors que des créneaux restent libres: %d", rr.Code)
		}
	}()
	<-entered

	close(release)
	wg.Wait()
}

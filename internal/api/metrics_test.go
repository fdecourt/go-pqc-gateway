package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

// TestMetrics_RenderExpositionFormat valide la structure de l'exposition texte Prometheus :
// présence des séries, cumul monotone des buckets, et cohérence entre _count et _bucket{le="+Inf"}.
func TestMetrics_RenderExpositionFormat(t *testing.T) {
	m := NewMetrics("9.9.9", "ML-KEM-768+AES-256-GCM", []string{"/encrypt"})

	m.ObserveRequest("/encrypt", http.StatusOK, 300*time.Microsecond)
	m.ObserveRequest("/encrypt", http.StatusOK, 3*time.Millisecond)
	m.ObserveRequest("/encrypt", http.StatusBadRequest, 12*time.Second)
	m.ObserveRateLimited()
	m.ObservePanic()

	out := m.Render()

	required := []string{
		`pqc_build_info{version="9.9.9",algorithm="ML-KEM-768+AES-256-GCM"} 1`,
		"pqc_rate_limited_total 1",
		"pqc_panics_recovered_total 1",
		`pqc_requests_total{path="/encrypt",status="200"} 2`,
		`pqc_requests_total{path="/encrypt",status="400"} 1`,
		`pqc_request_duration_seconds_count{path="/encrypt"} 3`,
		`pqc_request_duration_seconds_bucket{path="/encrypt",le="+Inf"} 3`,
		"# TYPE pqc_request_duration_seconds histogram",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("série absente de l'exposition: %s", want)
		}
	}

	// Le bucket 0.0005 ne doit contenir que la requête de 300 µs.
	if !strings.Contains(out, `pqc_request_duration_seconds_bucket{path="/encrypt",le="0.0005"} 1`) {
		t.Error("cumul du premier bucket incorrect")
	}
	// La requête de 12 s dépasse la borne haute : elle n'apparaît que dans +Inf.
	if !strings.Contains(out, `pqc_request_duration_seconds_bucket{path="/encrypt",le="5"} 2`) {
		t.Error("cumul du dernier bucket borné incorrect")
	}

	// Invariant Prometheus : les buckets doivent être monotones croissants au sein d'une
	// même série. Le cumul se réinitialise donc à chaque changement de route.
	prev := make(map[string]uint64)
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "pqc_request_duration_seconds_bucket") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("ligne de bucket malformée: %q", line)
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("valeur de bucket illisible: %q", line)
		}
		serie := fields[0][:strings.Index(fields[0], ",le=")]
		if v < prev[serie] {
			t.Fatalf("cumul non monotone: %q (précédent %d)", line, prev[serie])
		}
		prev[serie] = v
	}
}

// TestMetrics_EndpointAndMiddleware valide l'exposition HTTP de /metrics et la comptabilisation
// effective des requêtes traversant la chaîne complète du routeur.
func TestMetrics_EndpointAndMiddleware(t *testing.T) {
	cfg := &config.Config{
		MaxPayloadBytes: 4096,
		MetricsEnabled:  true,
		LogFormat:       "json",
		LogLevel:        "info",
	}
	r := NewRouter(cfg, crypto.NewMockEngine())
	defer r.Close()

	if r.Metrics() == nil {
		t.Fatal("collecteur de métriques absent alors que MetricsEnabled est vrai")
	}

	// Deux requêtes nominales, puis lecture de l'exposition.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/health attendu 200, obtenu %d", rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics attendu 200, obtenu %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type inattendu pour /metrics: %q", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `pqc_requests_total{path="/health",status="200"} 2`) {
		t.Errorf("les requêtes /health ne sont pas comptabilisées:\n%s", body)
	}

	// /metrics reste soumis aux en-têtes de sécurité de la chaîne.
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("/metrics servi sans en-têtes de sécurité")
	}
	if rec.Header().Get("X-Correlation-ID") == "" {
		t.Error("/metrics servi sans identifiant de corrélation")
	}
}

// TestMetrics_DisabledLeavesNoEndpoint vérifie que METRICS_ENABLED=false ne publie aucune route.
func TestMetrics_DisabledLeavesNoEndpoint(t *testing.T) {
	cfg := &config.Config{
		MaxPayloadBytes: 4096,
		MetricsEnabled:  false,
		LogFormat:       "json",
		LogLevel:        "info",
	}
	r := NewRouter(cfg, crypto.NewMockEngine())
	defer r.Close()

	if r.Metrics() != nil {
		t.Fatal("collecteur instancié alors que MetricsEnabled est faux")
	}

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/metrics devait renvoyer 404 quand la collecte est désactivée, obtenu %d", rec.Code)
	}
}

// TestMetrics_PanicAndRateLimitCounters valide le comptage des paniques et des rejets de débit.
func TestMetrics_PanicAndRateLimitCounters(t *testing.T) {
	m := NewMetrics("test", "mock", []string{"/boom", "/encrypt"})

	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("panique simulée")
	})
	chain := MetricsMiddleware(m)(RecoveryMiddleware(m)(panicking))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("attendu 500 après panique, obtenu %d", rec.Code)
	}

	out := m.Render()
	if !strings.Contains(out, "pqc_panics_recovered_total 1") {
		t.Error("panique non comptabilisée")
	}
	// Metrics étant à l'extérieur de Recovery, la requête est bien enregistrée en 500.
	if !strings.Contains(out, `pqc_requests_total{path="/boom",status="500"} 1`) {
		t.Errorf("requête paniquée non enregistrée en 500:\n%s", out)
	}

	limiter := NewIPRateLimiter(1, 1)
	defer limiter.Stop()
	rl := RateLimitMiddleware(limiter, false, m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/encrypt", nil)
		req.RemoteAddr = "198.51.100.5:4444"
		rl.ServeHTTP(httptest.NewRecorder(), req)
	}
	if strings.Contains(m.Render(), "pqc_rate_limited_total 0\n") {
		t.Error("aucun rejet comptabilisé alors que la limite a été dépassée")
	}
}

// TestMetrics_EndpointRejectsNonGET vérifie que /metrics n'accepte que GET (fail-closed sur la méthode).
func TestMetrics_EndpointRejectsNonGET(t *testing.T) {
	m := NewMetrics("test", "mock", []string{metricsPath})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		m.ServeMetrics(rec, httptest.NewRequest(method, "/metrics", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /metrics: attendu 405, obtenu %d", method, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	m.ServeMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: attendu 200, obtenu %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pqc_uptime_seconds") {
		t.Error("exposition incomplète sur GET /metrics")
	}
}

// TestMetrics_UnknownPathsAreAggregated verrouille la borne de cardinalité : un chemin
// contrôlé par l'appelant ne doit jamais créer de série, ni apparaître dans l'exposition.
func TestMetrics_UnknownPathsAreAggregated(t *testing.T) {
	m := NewMetrics("test", "mock", []string{"/encrypt"})

	base := strings.Count(m.Render(), "pqc_requests_total{")

	const flood = 5000
	for i := 0; i < flood; i++ {
		m.ObserveRequest("/scan-"+strconv.Itoa(i), http.StatusNotFound, time.Millisecond)
	}

	out := m.Render()

	if strings.Contains(out, "/scan-") {
		t.Error("un chemin non routé a fui dans les étiquettes exposées")
	}
	if got := strings.Count(out, "pqc_requests_total{"); got != base+1 {
		t.Errorf("cardinalité non bornée: %d séries après %d chemins uniques (attendu %d)", got, flood, base+1)
	}
	want := `pqc_requests_total{path="` + unmatchedPathLabel + `",status="404"} ` + strconv.Itoa(flood)
	if !strings.Contains(out, want) {
		t.Errorf("agrégat des chemins inconnus absent ou incorrect, attendu: %s", want)
	}
	if !strings.Contains(out, `pqc_request_duration_seconds_count{path="`+unmatchedPathLabel+`"} `+strconv.Itoa(flood)) {
		t.Error("latences des chemins inconnus non agrégées")
	}
}

// TestRouter_MetricsCardinalityIsBounded valide la borne sur la chaîne complète : la taille
// de l'exposition ne dépend pas du trafic reçu, ce qui neutralise l'amplification du scrape.
func TestRouter_MetricsCardinalityIsBounded(t *testing.T) {
	cfg := &config.Config{
		MaxPayloadBytes: 4096,
		MetricsEnabled:  true,
		LogFormat:       "json",
		LogLevel:        "info",
	}
	r := NewRouter(cfg, crypto.NewMockEngine())
	defer r.Close()

	scrape := func() string {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, metricsPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s attendu 200, obtenu %d", metricsPath, rec.Code)
		}
		return rec.Body.String()
	}

	inonder := func(depuis, jusqua int) {
		for i := depuis; i < jusqua; i++ {
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inonde-"+strconv.Itoa(i), nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("chemin inconnu attendu 404, obtenu %d", rec.Code)
			}
		}
	}

	// Référence prise à chaud : un chemin inconnu a déjà créé la série d'agrégation, et un
	// premier scrape a créé la sienne (l'observation d'une requête suit sa réponse).
	inonder(0, 1)
	scrape()
	avant := scrape()

	inonder(1, 1000)
	apres := scrape()

	if strings.Contains(apres, "/inonde-") {
		t.Error("chemin inconnu exposé comme étiquette de métrique")
	}
	if got, want := strings.Count(apres, "pqc_requests_total{"), strings.Count(avant, "pqc_requests_total{"); got != want {
		t.Errorf("nombre de séries variable: %d avant, %d après 999 chemins uniques de plus", want, got)
	}
	// Seuls des chiffres de compteurs grandissent : la taille de l'exposition ne doit pas
	// suivre le trafic reçu, sinon un scrape devient un vecteur d'amplification.
	if delta := len(apres) - len(avant); delta > 64 {
		t.Errorf("taille de l'exposition sensible au trafic: +%d octets pour 999 chemins uniques", delta)
	}
}

// BenchmarkMetricsObserveRequest mesure le chemin chaud d'instrumentation.
// Objectif : zéro allocation, aucune contention entre goroutines.
func BenchmarkMetricsObserveRequest(b *testing.B) {
	m := NewMetrics("bench", "mock", []string{"/encrypt"})
	m.ObserveRequest("/encrypt", http.StatusOK, time.Millisecond)
	m.ObserveRequest("/inconnu", http.StatusNotFound, time.Millisecond)

	for _, cas := range []struct {
		nom  string
		path string
	}{
		{"route_declaree", "/encrypt"},
		{"chemin_inconnu", "/inconnu"},
	} {
		b.Run(cas.nom, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					m.ObserveRequest(cas.path, http.StatusOK, 750*time.Microsecond)
				}
			})
		})
	}
}

package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// latencyBucketsSeconds définit les bornes du histogramme de latence (format Prometheus, secondes).
// Les bornes basses sont resserrées : une opération KEM+DEM nominale se situe sous la milliseconde.
var latencyBucketsSeconds = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// unmatchedPathLabel agrège sous une étiquette unique toute requête ne correspondant
// à aucune route déclarée. C'est la borne de cardinalité du collecteur : le chemin brut,
// contrôlé par l'appelant, n'atteint jamais les étiquettes exposées.
const unmatchedPathLabel = "other"

// routeMetric agrège les compteurs d'une route unique sans verrou sur le chemin chaud.
type routeMetric struct {
	total       atomic.Uint64
	byStatus    sync.Map // int (code HTTP) -> *atomic.Uint64
	sumMicros   atomic.Uint64
	bucketCount []atomic.Uint64
}

func newRouteMetric() *routeMetric {
	return &routeMetric{bucketCount: make([]atomic.Uint64, len(latencyBucketsSeconds)+1)}
}

func (m *routeMetric) observe(status int, d time.Duration) {
	m.total.Add(1)

	// Les codes HTTP proviennent des gestionnaires du service : l'ensemble est borné.
	// Un Load avant LoadOrStore évite d'allouer un compteur à chaque requête.
	counter, ok := m.byStatus.Load(status)
	if !ok {
		counter, _ = m.byStatus.LoadOrStore(status, new(atomic.Uint64))
	}
	counter.(*atomic.Uint64).Add(1)

	seconds := d.Seconds()
	// La somme est cumulée en microsecondes entières pour rester exacte en atomique.
	// Une durée négative est impossible avec l'horloge monotone, mais le garde évite
	// toute conversion int64 -> uint64 non bornée (G115).
	if micros := d.Microseconds(); micros > 0 {
		m.sumMicros.Add(uint64(micros))
	}

	idx := sort.SearchFloat64s(latencyBucketsSeconds, seconds)
	if idx >= len(latencyBucketsSeconds) {
		idx = len(latencyBucketsSeconds)
	}
	m.bucketCount[idx].Add(1)
}

// Metrics collecte les compteurs opérationnels du service, sans dépendance externe.
// Le rendu suit le format d'exposition texte Prometheus, directement scrapable.
//
// La cardinalité est fixée à la construction : une série par route déclarée, plus une
// série d'agrégation pour tout le reste. Aucune entrée n'est créée pendant le service,
// ce qui rend le chemin chaud sans allocation ni verrou (lecture d'une table immuable)
// et le coût d'un scrape indépendant du trafic reçu.
type Metrics struct {
	startTime      time.Time
	routes         map[string]*routeMetric // immuable après NewMetrics : lecture concurrente sûre
	unmatched      *routeMetric
	sortedPaths    []string // clés de routes triées, calculées une fois pour un rendu déterministe
	rateLimited    atomic.Uint64
	panicsRecoved  atomic.Uint64
	serviceVersion string
	algorithm      string
}

// NewMetrics initialise le collecteur de métriques du service.
// paths énumère les routes déclarées par le routeur : elles seules obtiennent une
// étiquette propre. Un chemin absent de cette liste est comptabilisé sous "other".
func NewMetrics(serviceVersion, algorithm string, paths []string) *Metrics {
	routes := make(map[string]*routeMetric, len(paths))
	sorted := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, exists := routes[p]; exists {
			continue
		}
		routes[p] = newRouteMetric()
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	return &Metrics{
		startTime:      time.Now(),
		routes:         routes,
		unmatched:      newRouteMetric(),
		sortedPaths:    sorted,
		serviceVersion: serviceVersion,
		algorithm:      algorithm,
	}
}

// ObserveRequest enregistre l'issue d'une requête HTTP terminée.
// Un chemin inconnu est agrégé sous "other" : la table des séries ne croît jamais.
func (m *Metrics) ObserveRequest(path string, status int, d time.Duration) {
	entry, ok := m.routes[path]
	if !ok {
		entry = m.unmatched
	}
	entry.observe(status, d)
}

// ObserveRateLimited incrémente le compteur de rejets par limitation de débit.
func (m *Metrics) ObserveRateLimited() { m.rateLimited.Add(1) }

// ObservePanic incrémente le compteur de paniques interceptées.
func (m *Metrics) ObservePanic() { m.panicsRecoved.Add(1) }

// routeSeries associe une étiquette de route à ses compteurs, pour le rendu.
type routeSeries struct {
	path   string
	metric *routeMetric
}

// series retourne les séries à exposer dans un ordre déterministe : les routes déclarées
// triées, puis l'agrégat des chemins inconnus. La longueur est fixe pour la durée de vie
// du collecteur, ce qui borne le coût et la taille d'un scrape.
func (m *Metrics) series() []routeSeries {
	out := make([]routeSeries, 0, len(m.sortedPaths)+1)
	for _, p := range m.sortedPaths {
		out = append(out, routeSeries{path: p, metric: m.routes[p]})
	}
	return append(out, routeSeries{path: unmatchedPathLabel, metric: m.unmatched})
}

// escapeLabel échappe une valeur d'étiquette selon la spécification d'exposition Prometheus.
func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// Render produit l'exposition texte Prometheus de l'ensemble des métriques collectées.
func (m *Metrics) Render() string {
	var b strings.Builder

	b.WriteString("# HELP pqc_build_info Informations statiques de build du service.\n")
	b.WriteString("# TYPE pqc_build_info gauge\n")
	b.WriteString(`pqc_build_info{version="` + escapeLabel(m.serviceVersion) +
		`",algorithm="` + escapeLabel(m.algorithm) + "\"} 1\n")

	b.WriteString("# HELP pqc_uptime_seconds Durée de fonctionnement du service en secondes.\n")
	b.WriteString("# TYPE pqc_uptime_seconds gauge\n")
	b.WriteString("pqc_uptime_seconds " + strconv.FormatFloat(time.Since(m.startTime).Seconds(), 'f', 3, 64) + "\n")

	b.WriteString("# HELP pqc_rate_limited_total Nombre de requêtes rejetées par la limitation de débit.\n")
	b.WriteString("# TYPE pqc_rate_limited_total counter\n")
	b.WriteString("pqc_rate_limited_total " + strconv.FormatUint(m.rateLimited.Load(), 10) + "\n")

	b.WriteString("# HELP pqc_panics_recovered_total Nombre de paniques interceptées par le middleware de récupération.\n")
	b.WriteString("# TYPE pqc_panics_recovered_total counter\n")
	b.WriteString("pqc_panics_recovered_total " + strconv.FormatUint(m.panicsRecoved.Load(), 10) + "\n")

	series := m.series()

	b.WriteString("# HELP pqc_requests_total Nombre total de requêtes HTTP traitées. " +
		"L'étiquette path vaut \"" + unmatchedPathLabel + "\" pour tout chemin hors routes déclarées.\n")
	b.WriteString("# TYPE pqc_requests_total counter\n")
	for _, s := range series {
		p, rm := s.path, s.metric

		codes := make([]int, 0, 4)
		rm.byStatus.Range(func(k, _ any) bool {
			codes = append(codes, k.(int))
			return true
		})
		sort.Ints(codes)

		for _, code := range codes {
			c, ok := rm.byStatus.Load(code)
			if !ok {
				continue
			}
			b.WriteString(`pqc_requests_total{path="` + escapeLabel(p) + `",status="` +
				strconv.Itoa(code) + "\"} " + strconv.FormatUint(c.(*atomic.Uint64).Load(), 10) + "\n")
		}
	}

	b.WriteString("# HELP pqc_request_duration_seconds Latence des requêtes HTTP par route.\n")
	b.WriteString("# TYPE pqc_request_duration_seconds histogram\n")
	for _, s := range series {
		p, rm := s.path, s.metric
		label := `{path="` + escapeLabel(p) + `",le="`

		var cumulative uint64
		for i, bound := range latencyBucketsSeconds {
			cumulative += rm.bucketCount[i].Load()
			b.WriteString("pqc_request_duration_seconds_bucket" + label +
				strconv.FormatFloat(bound, 'g', -1, 64) + "\"} " + strconv.FormatUint(cumulative, 10) + "\n")
		}
		cumulative += rm.bucketCount[len(latencyBucketsSeconds)].Load()
		b.WriteString("pqc_request_duration_seconds_bucket" + label + "+Inf\"} " +
			strconv.FormatUint(cumulative, 10) + "\n")

		sumSeconds := float64(rm.sumMicros.Load()) / 1e6
		b.WriteString(`pqc_request_duration_seconds_sum{path="` + escapeLabel(p) + "\"} " +
			strconv.FormatFloat(sumSeconds, 'f', 6, 64) + "\n")
		b.WriteString(`pqc_request_duration_seconds_count{path="` + escapeLabel(p) + "\"} " +
			strconv.FormatUint(rm.total.Load(), 10) + "\n")
	}

	return b.String()
}

// MetricsMiddleware mesure la latence et l'issue de chaque requête HTTP.
func MetricsMiddleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			interceptor := &responseWriterInterceptor{ResponseWriter: w}

			next.ServeHTTP(interceptor, r)

			status := interceptor.statusCode
			if status == 0 {
				status = http.StatusOK
			}
			m.ObserveRequest(r.URL.Path, status, time.Since(start))
		})
	}
}

// ServeMetrics expose les métriques au format texte Prometheus.
func (m *Metrics) ServeMetrics(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// #nosec G104 -- écriture best-effort sur la réponse HTTP, aucune action de repli possible
	_, _ = w.Write([]byte(m.Render()))
}

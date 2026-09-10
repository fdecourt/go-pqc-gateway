package api

import (
	"net/http"

	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

// metricsPath est la route d'exposition Prometheus, publiée uniquement si la collecte est activée.
const metricsPath = "/metrics"

// Router encapsule le multiplexeur HTTP et gère le cycle de vie des ressources d'arrière-plan.
type Router struct {
	http.Handler
	limiter *IPRateLimiter
	metrics *Metrics
}

// Close libère proprement les ressources et arrête les goroutines d'arrière-plan (zéro fuite de goroutines).
func (r *Router) Close() {
	if r.limiter != nil {
		r.limiter.Stop()
	}
}

// Metrics expose le collecteur de métriques du routeur (nil si la collecte est désactivée).
func (r *Router) Metrics() *Metrics { return r.metrics }

// NewRouter initialise le routeur HTTP standard et applique la chaîne de middlewares.
func NewRouter(cfg *config.Config, engine crypto.Engine) *Router {
	mux := http.NewServeMux()
	handler := NewHandler(engine, cfg.AllowLegacyEnvelopes)

	// Table unique du contrat de routage. Elle alimente à la fois l'enregistrement des
	// gestionnaires et la pré-déclaration des séries de métriques : une route ajoutée ici
	// est instrumentée sans autre intervention, et aucune des deux listes ne peut dériver.
	routes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/health", handler.HealthCheck},
		{"/public-key", handler.GetPublicKey},
		{"/encrypt", handler.Encrypt},
		{"/decrypt", handler.Decrypt},

		// Envelope Encryption (KMS Pattern)
		{"/wrap-key", handler.WrapKey},
		{"/unwrap-key", handler.UnwrapKey},
		{"/generate-key", handler.GenerateDataKey},

		// Primitives KEM pures (Key Agreement direct)
		{"/kem/encapsulate", handler.KEMEncapsulate},
		{"/kem/decapsulate", handler.KEMDecapsulate},
	}

	paths := make([]string, 0, len(routes)+1)
	for _, rt := range routes {
		mux.HandleFunc(rt.path, rt.handler)
		paths = append(paths, rt.path)
	}

	var metrics *Metrics
	if cfg.MetricsEnabled {
		paths = append(paths, metricsPath)
		metrics = NewMetrics(config.ServiceVersion, engine.Name(), paths)
		mux.HandleFunc(metricsPath, metrics.ServeMetrics)
	}

	// Chaînage des middlewares. L'ordre d'application est inverse de l'ordre d'exécution :
	// le dernier appliqué est le plus externe. Exécution effective :
	// CorrelationID -> Logger -> Metrics -> Recovery -> SecurityHeaders -> RateLimit -> MaxBodySize -> mux
	var chain http.Handler = mux
	chain = MaxBodySizeMiddleware(cfg.MaxPayloadBytes)(chain)

	var limiter *IPRateLimiter
	if cfg.RateLimitRPS > 0 {
		burst := cfg.RateLimitBurst
		if burst <= 0 {
			burst = 100
		}
		limiter = NewIPRateLimiter(cfg.RateLimitRPS, burst)
		chain = RateLimitMiddleware(limiter, cfg.TrustProxy, metrics)(chain)
	}

	chain = SecurityHeadersMiddleware(chain)
	chain = RecoveryMiddleware(metrics)(chain)
	if metrics != nil {
		// Placé à l'extérieur de Recovery afin qu'une panique interceptée soit comptabilisée en 500.
		chain = MetricsMiddleware(metrics)(chain)
	}
	if cfg.AccessLog {
		chain = LoggerMiddleware(chain)
	}
	chain = CorrelationIDMiddleware(chain)

	return &Router{
		Handler: chain,
		limiter: limiter,
		metrics: metrics,
	}
}

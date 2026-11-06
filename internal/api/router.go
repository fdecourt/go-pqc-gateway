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
	handler := NewHandler(engine, HandlerOptions{BindClientIdentity: cfg.BindClientIdentity, Audit: cfg.AuditLog})

	// Table unique du contrat de routage. Elle alimente à la fois l'enregistrement des
	// gestionnaires et la pré-déclaration des séries de métriques : une route ajoutée ici
	// est instrumentée sans autre intervention, et aucune des deux listes ne peut dériver.
	// Limites de corps : seules /encrypt et /decrypt acceptent de gros corps ; /decrypt
	// reçoit la marge de l'enveloppe, pour que tout chiffré produit soit déchiffrable
	// (voir OpenBodyLimit). Toute autre route est bornée à SmallBodyLimit.
	sealLimit := cfg.MaxPayloadBytes
	openLimit := OpenBodyLimit(cfg.MaxPayloadBytes)

	routes := []struct {
		path      string
		handler   http.HandlerFunc
		bodyLimit int64
	}{
		{"/health", handler.HealthCheck, SmallBodyLimit},
		{"/public-key", handler.GetPublicKey, SmallBodyLimit},
		{"/encrypt", handler.Encrypt, sealLimit},
		{"/decrypt", handler.Decrypt, openLimit},

		// Envelope Encryption (KMS Pattern) : des clés de 16 à 128 octets
		{"/wrap-key", handler.WrapKey, SmallBodyLimit},
		{"/unwrap-key", handler.UnwrapKey, SmallBodyLimit},
		{"/generate-key", handler.GenerateDataKey, SmallBodyLimit},

		// Primitives KEM pures (Key Agreement direct)
		{"/kem/encapsulate", handler.KEMEncapsulate, SmallBodyLimit},
		{"/kem/decapsulate", handler.KEMDecapsulate, SmallBodyLimit},
	}

	paths := make([]string, 0, len(routes)+1)
	limits := make(map[string]int64, len(routes))
	for _, rt := range routes {
		mux.HandleFunc(rt.path, rt.handler)
		paths = append(paths, rt.path)
		limits[rt.path] = rt.bodyLimit
	}
	limitFor := func(path string) int64 {
		if l, ok := limits[path]; ok {
			return l
		}
		return SmallBodyLimit
	}

	var metrics *Metrics
	if cfg.MetricsEnabled {
		paths = append(paths, metricsPath)
		metrics = NewMetrics(config.ServiceVersion, engine.Name(), paths)
		mux.HandleFunc(metricsPath, metrics.ServeMetrics)
	}

	// Chaînage des middlewares. L'ordre d'application est inverse de l'ordre d'exécution :
	// le dernier appliqué est le plus externe. Exécution effective :
	// CorrelationID -> Logger -> Metrics -> Recovery -> SecurityHeaders -> PeerIdentity -> ClientCert (mTLS) -> Token -> RequireIdentity -> ContentType -> MaxBodySize -> RateLimit -> Concurrency -> mux
	// Le rate-limit précède le plafond de concurrence : une requête refusée n'occupe jamais de créneau.
	// MaxBodySize les précède tous deux : le corps d'une requête refusée est lu et jeté dans la limite.
	var chain http.Handler = mux
	clientIP := NewClientIPResolver(cfg.TrustedProxies)

	if cfg.MaxConcurrentRequests > 0 {
		chain = ConcurrencyLimitMiddleware(cfg.MaxConcurrentRequests, clientIP, metrics)(chain)
	}

	var limiter *IPRateLimiter
	if cfg.RateLimitRPS > 0 {
		burst := cfg.RateLimitBurst
		if burst <= 0 {
			burst = 100
		}
		limiter = NewIPRateLimiter(cfg.RateLimitRPS, burst)
		chain = RateLimitMiddleware(limiter, clientIP, metrics)(chain)
	}

	chain = MaxBodySizeMiddleware(limitFor)(chain)
	chain = RequireContentTypeMiddleware(chain)
	if cfg.BindClientIdentity {
		chain = RequireIdentityMiddleware(chain)
	}
	if len(cfg.AuthTokens) > 0 {
		chain = RequireTokenMiddleware(cfg.AuthTokens)(chain)
	}
	if cfg.MTLSEnabled() {
		chain = RequireClientCertMiddleware(cfg.TLSClientAllowedNames)(chain)
	}
	chain = PeerIdentityMiddleware(chain)

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

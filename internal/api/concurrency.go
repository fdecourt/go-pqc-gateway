package api

import (
	"net/http"
	"sync"
	"time"
)

// concurrencyWait borne l'attente d'un créneau avant de répondre 503 : une file courte absorbe
// les pics, une file longue ne ferait que retarder la saturation mémoire.
const concurrencyWait = 500 * time.Millisecond

// perIPShare est la fraction des créneaux qu'une même source peut occuper (1/perIPShare).
const perIPShare = 4

// ipSlots compte les créneaux occupés par adresse source.
type ipSlots struct {
	mu    sync.Mutex
	inUse map[string]int
	max   int
}

func (s *ipSlots) acquire(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inUse[ip] >= s.max {
		return false
	}
	s.inUse[ip]++
	return true
}

func (s *ipSlots) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inUse[ip] <= 1 {
		delete(s.inUse, ip) // la table ne retient que les sources actives
		return
	}
	s.inUse[ip]--
}

// ConcurrencyLimitMiddleware borne le nombre de requêtes traitées simultanément.
//
// Chaque requête JSON peut tenir plusieurs copies de sa charge en mémoire (corps, Base64
// décodé, chiffré, ré-encodage) : sans borne, quelques requêtes parallèles de taille maximale
// suffisent à dépasser la limite mémoire du conteneur. Le plafond rend l'empreinte maximale
// prévisible (≈ limit × copies × MAX_PAYLOAD_BYTES).
//
// Une requête occupe son créneau pendant la lecture de son corps : un client lent le garde
// jusqu'au ReadTimeout du serveur. Une même source ne peut donc occuper qu'un quart des
// créneaux, pour qu'un client unique ne bloque pas le service. Résiduel assumé : un attaquant
// disposant de nombreuses adresses peut encore saturer les créneaux (comme le rate-limit par IP).
//
// /health et /metrics restent hors quota pour que la supervision voie un service saturé
// plutôt qu'un service muet. Le collecteur de métriques est optionnel (nil : pas de comptage).
func ConcurrencyLimitMiddleware(limit int, clientIP ClientIPFunc, m *Metrics) func(http.Handler) http.Handler {
	slots := make(chan struct{}, limit)
	perIP := &ipSlots{inUse: make(map[string]int), max: max(1, limit/perIPShare)}

	reject := func(w http.ResponseWriter, r *http.Request) {
		discardBody(w, r)
		if m != nil {
			m.ObserveOverloaded()
		}
		w.Header().Set("Retry-After", "1")
		respondError(w, http.StatusServiceUnavailable, "service saturé", "trop de requêtes cryptographiques simultanées")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == metricsPath {
				next.ServeHTTP(w, r)
				return
			}

			ip := clientIP(r)
			if !perIP.acquire(ip) {
				reject(w, r)
				return
			}
			defer perIP.release(ip)

			// Chemin rapide : un créneau libre se prend sans armer de minuterie.
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				next.ServeHTTP(w, r)
				return
			default:
			}

			timer := time.NewTimer(concurrencyWait)
			defer timer.Stop()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				next.ServeHTTP(w, r)
			case <-timer.C:
				reject(w, r)
			case <-r.Context().Done():
				// Client parti pendant l'attente : rien à répondre.
			}
		})
	}
}

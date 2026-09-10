package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

type contextKey string

const CorrelationIDKey contextKey = "correlation_id"

// GetCorrelationID extrait l'identifiant de corrélation du contexte de la requête.
func GetCorrelationID(r *http.Request) string {
	if v, ok := r.Context().Value(CorrelationIDKey).(string); ok {
		return v
	}
	return ""
}

// responseWriterInterceptor intercepte le code HTTP pour le logging d'accès.
type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
	bytesCount int
}

func (w *responseWriterInterceptor) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterInterceptor) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesCount += n
	return n, err
}

// CorrelationIDMiddleware garantit l'affectation et la propagation d'un identifiant de corrélation
// unique (X-Correlation-ID) sur chaque requête et réponse HTTP.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Correlation-ID")
		if cid == "" {
			cid = r.Header.Get("X-Request-ID")
		}
		if cid == "" {
			var b [16]byte
			_, _ = rand.Read(b[:])
			cid = hex.EncodeToString(b[:])
		}

		w.Header().Set("X-Correlation-ID", cid)
		r = r.WithContext(context.WithValue(r.Context(), CorrelationIDKey, cid))
		next.ServeHTTP(w, r)
	})
}

// LoggerMiddleware journalise chaque requête HTTP entrante avec méthode, identifiant de corrélation, durée et statut.
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		interceptor := &responseWriterInterceptor{ResponseWriter: w}

		next.ServeHTTP(interceptor, r)

		duration := time.Since(start)
		if interceptor.statusCode == 0 {
			interceptor.statusCode = http.StatusOK
		}

		slog.Info("http_request",
			slog.String("correlation_id", GetCorrelationID(r)),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", interceptor.statusCode),
			slog.Int64("duration_us", duration.Microseconds()),
			slog.Int("bytes", interceptor.bytesCount),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
		)
	})
}

// RecoveryMiddleware intercepte les paniques inattendues et renvoie une réponse JSON 500 propre.
// Le collecteur de métriques est optionnel : un nil désactive simplement le comptage.
func RecoveryMiddleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if m != nil {
						m.ObservePanic()
					}
					slog.Error("panic_recovered",
						slog.String("correlation_id", GetCorrelationID(r)),
						slog.String("path", r.URL.Path),
						slog.Any("panic", rec),
						slog.String("stack", string(debug.Stack())),
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "erreur interne du serveur cryptographique",
						Code:    http.StatusInternalServerError,
						Details: "une condition inattendue a été rencontrée lors de l'exécution",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware injecte des en-têtes HTTP de sécurité stricts (HSTS, CSP, nosniff, etc.).
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")
		next.ServeHTTP(w, r)
	})
}

// MaxBodySizeMiddleware limite la taille maximale du corps de requête pour prévenir les attaques DoS mémoire.
func MaxBodySizeMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && maxBytes > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

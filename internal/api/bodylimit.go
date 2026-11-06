package api

import (
	"math"
	"net/http"
)

// SmallBodyLimit borne le corps des routes qui ne transportent que des clés et des métadonnées
// (/wrap-key, /unwrap-key, /generate-key, /kem/*, routes GET et chemins inconnus). Une clé
// enveloppée, une clé publique ML-KEM-1024 hybride en Base64 (~2,2 Kio) et un contexte de 4 Kio
// échappé y tiennent largement : seules /encrypt et /decrypt acceptent de gros corps.
const SmallBodyLimit = 64 << 10

// openEnvelopeMargin couvre, au déchiffrement, ce que l'enveloppe ajoute au clair : clé
// encapsulée (1 600 octets au plus, 2 136 en Base64), nonce, tag, métadonnées, contexte.
const openEnvelopeMargin = 64 << 10

// OpenBodyLimit renvoie la limite de corps de /decrypt pour une limite de chiffrement sealLimit.
//
// Garantie : tout chiffré produit par /encrypt (JSON ou binaire) avec un corps d'au plus
// sealLimit octets est accepté par /decrypt, y compris réencodé par un client qui échappe
// les « / » du Base64 (json_encode de PHP). Un clair de P octets donne au plus
// 4/3·(P+16) octets de Base64 (+1,6 % avec les « \/ ») : 1,5·P + 64 Kio laisse une marge.
func OpenBodyLimit(sealLimit int64) int64 {
	if sealLimit <= 0 {
		return SmallBodyLimit
	}
	if sealLimit > (math.MaxInt64-openEnvelopeMargin)/3*2 {
		return math.MaxInt64
	}
	return sealLimit + sealLimit/2 + openEnvelopeMargin
}

// bodyLimit renvoie la limite de corps posée par MaxBodySizeMiddleware (SmallBodyLimit sinon).
func bodyLimit(r *http.Request) int64 {
	if info := infoOf(r); info != nil {
		return info.bodyLimit
	}
	return SmallBodyLimit
}

// MaxBodySizeMiddleware borne le corps de chaque requête selon sa route (limitFor), avant
// tout traitement : une requête dont Content-Length dépasse déjà la limite reçoit 413 sans que
// son corps soit lu au-delà de la limite. La limite voyage dans le contexte pour que les
// lecteurs dimensionnent leur tampon sans croire Content-Length.
func MaxBodySizeMiddleware(limitFor func(path string) int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := limitFor(r.URL.Path)
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			ensureInfo(&r).bodyLimit = limit
			if r.ContentLength > limit {
				discardBody(w, r)
				respondError(w, http.StatusRequestEntityTooLarge, "charge utile trop volumineuse", "la taille dépasse la limite autorisée pour cette route")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"pq-crypto-service/internal/secmem"
)

// requireMethod valide que la méthode HTTP correspond exactement à la méthode attendue.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		respondError(w, http.StatusMethodNotAllowed, "méthode non autorisée", "seul "+method+" est supporté")
		return false
	}
	return true
}

// errBodyTooLarge est renvoyée par readRequestBody au-delà de la limite de la route.
var errBodyTooLarge = errors.New("corps de requête trop volumineux")

// readRequestBody lit le corps de la requête dans un tampon possédé et borné par la limite de
// la route (voir MaxBodySizeMiddleware). L'appelant efface le tampon (secmem.Wipe) après usage.
// Content-Length ne sert qu'à dimensionner le tampon et n'est jamais cru au-delà de la limite.
func readRequestBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	body, err := secmem.ReadAll(r.Body, r.ContentLength, bodyLimit(r))
	var maxBytesErr *http.MaxBytesError
	if errors.Is(err, secmem.ErrTooLarge) || errors.As(err, &maxBytesErr) {
		return nil, errBodyTooLarge
	}
	return body, err
}

// respondBodyError traduit une erreur de lecture du corps en réponse HTTP.
func respondBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		respondError(w, http.StatusRequestEntityTooLarge, "charge utile trop volumineuse", "la taille dépasse la limite autorisée pour cette route")
		return
	}
	respondError(w, http.StatusBadRequest, "erreur de lecture du corps", "corps de requête interrompu ou illisible")
}

// wiper est implémenté par les requêtes qui portent des champs secrets à effacer.
type wiper interface{ wipe() }

// bindJSON lit et décode strictement un corps JSON (voir secmem.DecodeStrict) dans dst.
// Le corps brut est effacé avant le retour, que le décodage réussisse ou non ; en cas d'échec,
// dst est aussi effacé. En cas de succès, l'appelant diffère dst.wipe().
func bindJSON(w http.ResponseWriter, r *http.Request, dst wiper, allowEmpty bool) bool {
	body, err := readRequestBody(r)
	if err != nil {
		respondBodyError(w, err)
		return false
	}
	err = secmem.DecodeStrict(body, dst, allowEmpty)
	secmem.Wipe(body)
	if err != nil {
		dst.wipe()
		respondError(w, http.StatusBadRequest, "corps JSON invalide", err.Error())
		return false
	}
	return true
}

// respondJSON sérialise et envoie une réponse JSON SANS donnée secrète (métadonnées, erreurs).
// Les réponses portant un secret passent par respondBuffer.
func respondJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// respondBuffer envoie un corps déjà construit dans un tampon effaçable, puis l'efface.
// Content-Length est posé : le corps part en une écriture, sans encodage par blocs.
func respondBuffer(w http.ResponseWriter, statusCode int, contentType string, buf *secmem.Buffer) {
	defer buf.Wipe()
	setContentType(w, contentType)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes()) // #nosec G104 -- en-têtes envoyés : une erreur d'écriture n'a plus de destinataire
}

// Valeurs d'en-tête Content-Type partagées (jamais modifiées par net/http) : aucune allocation par réponse.
var contentTypeValues = map[string][]string{
	jsonContentType: {jsonContentType},
	binaryMediaType: {binaryMediaType},
}

func setContentType(w http.ResponseWriter, contentType string) {
	if v, ok := contentTypeValues[contentType]; ok {
		w.Header()["Content-Type"] = v
		return
	}
	w.Header().Set("Content-Type", contentType)
}

// respondError renvoie une erreur JSON standardisée.
func respondError(w http.ResponseWriter, statusCode int, message, details string) {
	respondJSON(w, statusCode, ErrorResponse{
		Error:   message,
		Code:    statusCode,
		Details: details,
	})
}

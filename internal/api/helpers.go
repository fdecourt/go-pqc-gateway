package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// requireMethod valide que la méthode HTTP correspond exactement à la méthode attendue.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		respondError(w, http.StatusMethodNotAllowed, "méthode non autorisée", "seul "+method+" est supporté")
		return false
	}
	return true
}

// decodeJSON centralise la désérialisation JSON stricte, le rejet des flux composites et l'interdiction des champs inconnus (DRY).
func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}, optional bool) bool {
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if optional && errors.Is(err, io.EOF) {
			return true // Corps vide valide lorsque le payload JSON est optionnel
		}
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			respondError(w, http.StatusRequestEntityTooLarge, "charge utile trop volumineuse", "la taille dépasse la limite autorisée")
			return false
		}
		respondError(w, http.StatusBadRequest, "corps JSON invalide", err.Error())
		return false
	}

	// Interdiction de second document JSON dans le même flux (rejet des flux composites)
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		respondError(w, http.StatusBadRequest, "corps JSON invalide", "second document JSON ou données superflues après la fin du document")
		return false
	}

	return true
}

// bindJSON désérialise un corps JSON obligatoire.
func bindJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	return decodeJSON(w, r, dst, false)
}

// bindOptionalJSON désérialise un corps JSON optionnel. Si le corps est vide (io.EOF), il n'échoue pas.
func bindOptionalJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	return decodeJSON(w, r, dst, true)
}

// respondJSON sérialise et envoie la réponse JSON avec le code HTTP spécifié.
func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// respondError renvoie une erreur JSON standardisée.
func respondError(w http.ResponseWriter, statusCode int, message, details string) {
	respondJSON(w, statusCode, ErrorResponse{
		Error:   message,
		Code:    statusCode,
		Details: details,
	})
}

package keystore

import (
	"context"
	"errors"
)

var (
	ErrSecretNotFound = errors.New("secret non trouvé dans le coffre")
	// ErrBootstrapForbidden signale un état du coffre dans lequel générer une nouvelle paire
	// rendrait des données existantes illisibles : le service doit refuser de démarrer.
	ErrBootstrapForbidden = errors.New("état du coffre interdisant la génération d'une nouvelle paire")
)

// Store lit et écrit la paire de clés du service. Les tranches renvoyées par FetchKeys
// appartiennent à l'appelant, qui efface sk après usage ; StoreKeys n'en conserve aucune copie.
type Store interface {
	FetchKeys(ctx context.Context) (pkBytes []byte, skBytes []byte, err error)
	StoreKeys(ctx context.Context, pkBytes []byte, skBytes []byte) error
}

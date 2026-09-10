package keystore

import (
	"context"
	"errors"
)

var (
	ErrSecretNotFound = errors.New("secret non trouvé dans le coffre")
	ErrPartialKeypair = errors.New("demi-clé orpheline (état de paire de clés incomplet dans le coffre)")
)

type Store interface {
	FetchKeys(ctx context.Context) (pkBytes []byte, skBytes []byte, err error)
	StoreKeys(ctx context.Context, pkBytes []byte, skBytes []byte) error
}

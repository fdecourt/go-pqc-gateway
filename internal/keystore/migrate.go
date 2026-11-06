package keystore

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"pq-crypto-service/internal/secmem"
)

// ErrMigrationConflict signale que le coffre cible détient déjà une AUTRE paire : la
// migration est refusée plutôt que d'écraser l'une des deux.
var ErrMigrationConflict = errors.New("le coffre cible contient déjà une paire différente")

// MigrationResult décrit l'issue d'une migration réussie.
type MigrationResult int

const (
	// MigrationCopied : la paire a été écrite dans la cible, relue et vérifiée.
	MigrationCopied MigrationResult = iota + 1
	// MigrationAlreadyPresent : la cible détenait déjà exactement la même paire (rejeu sans effet).
	MigrationAlreadyPresent
)

// Migrate copie la paire de src vers dst, pour changer de coffre sans rendre une seule donnée
// illisible. La migration est conservative et rejouable :
//   - la source n'est jamais modifiée ni supprimée (retour arrière toujours possible) ;
//   - une cible qui contient déjà la même paire est laissée telle quelle ;
//   - une cible qui contient une autre paire est refusée (ErrMigrationConflict) ;
//   - après écriture, la cible est relue et comparée à la source.
func Migrate(ctx context.Context, src, dst Store) (MigrationResult, error) {
	pk, sk, err := src.FetchKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("lecture de la paire dans le coffre source: %w", err)
	}
	defer secmem.Wipe(sk)

	dpk, dsk, err := dst.FetchKeys(ctx)
	switch {
	case err == nil:
		same := samePair(pk, sk, dpk, dsk)
		secmem.Wipe(dsk)
		if !same {
			return 0, ErrMigrationConflict
		}
		return MigrationAlreadyPresent, nil
	case !errors.Is(err, ErrSecretNotFound):
		return 0, fmt.Errorf("lecture du coffre cible: %w", err)
	}

	if err := dst.StoreKeys(ctx, pk, sk); err != nil {
		return 0, fmt.Errorf("écriture dans le coffre cible: %w", err)
	}
	dpk, dsk, err = dst.FetchKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("relecture du coffre cible après écriture: %w", err)
	}
	defer secmem.Wipe(dsk)
	if !samePair(pk, sk, dpk, dsk) {
		return 0, fmt.Errorf("%w (relecture après écriture)", ErrMigrationConflict)
	}
	return MigrationCopied, nil
}

func samePair(pk, sk, opk, osk []byte) bool {
	return bytes.Equal(pk, opk) && subtle.ConstantTimeCompare(sk, osk) == 1
}

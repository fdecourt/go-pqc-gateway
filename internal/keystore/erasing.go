package keystore

import (
	"context"

	"pq-crypto-service/internal/secmem"
)

// WithErasure enveloppe un coffre pour que chaque échange avec lui s'exécute sous
// secmem.Do (runtime/secret).
//
// Un échange avec un coffre fait transiter des secrets par de la mémoire que le service ne
// peut pas effacer lui-même : jeton d'accès dans un en-tête HTTP (chaîne Go), tampons de
// net/http et de crypto/tls, réponse contenant la clé privée. Sous runtime/secret, ces
// allocations, y compris celles des goroutines du transport HTTP lancées pendant l'échange,
// sont effacées dès que le ramasse-miettes les libère. Tout coffre ouvert par le service passe
// par ici : un coffre ajouté plus tard est protégé sans rien faire de particulier.
//
// La connexion au coffre doit naître sous Do pour que ses goroutines soient couvertes : le
// client n'est utilisé que par ces méthodes, puis fermé (Close) au démarrage.
func WithErasure(s Store) Store {
	if s == nil {
		return nil
	}
	return erasingStore{s}
}

type erasingStore struct{ inner Store }

func (e erasingStore) FetchKeys(ctx context.Context) (pk, sk []byte, err error) {
	secmem.Do(func() { pk, sk, err = e.inner.FetchKeys(ctx) })
	return pk, sk, err
}

func (e erasingStore) StoreKeys(ctx context.Context, pk, sk []byte) (err error) {
	secmem.Do(func() { err = e.inner.StoreKeys(ctx, pk, sk) })
	return err
}

// Close ferme le coffre sous effacement : révocation du jeton, fermeture des connexions.
func (e erasingStore) Close() {
	if closer, ok := e.inner.(interface{ Close() }); ok {
		secmem.Do(closer.Close)
	}
}

// Unwrap renvoie le coffre enveloppé.
func (e erasingStore) Unwrap() Store { return e.inner }

package keystore_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"pq-crypto-service/internal/keystore"
)

// memStore est un coffre en mémoire qui respecte le contrat : jamais d'écrasement.
type memStore struct {
	pk, sk []byte
	writes int
}

func (m *memStore) FetchKeys(context.Context) ([]byte, []byte, error) {
	if m.pk == nil {
		return nil, nil, keystore.ErrSecretNotFound
	}
	return append([]byte(nil), m.pk...), append([]byte(nil), m.sk...), nil
}

func (m *memStore) StoreKeys(_ context.Context, pk, sk []byte) error {
	if m.pk != nil {
		return errors.New("paire déjà présente")
	}
	m.pk, m.sk = append([]byte(nil), pk...), append([]byte(nil), sk...)
	m.writes++
	return nil
}

func TestBundle_RoundTripAndChecks(t *testing.T) {
	pk, sk := []byte("public-key-bytes"), []byte("secret-key-bytes")
	b := keystore.EncodeBundle("ML-KEM-768", pk, sk, time.Unix(0, 0))
	raw := append([]byte(nil), b.Bytes()...)
	b.Wipe()

	gotPK, gotSK, err := keystore.ParseBundle(raw, "ml-kem-768")
	if err != nil || string(gotPK) != string(pk) || string(gotSK) != string(sk) {
		t.Fatalf("aller-retour du bundle : %v", err)
	}
	if _, _, err := keystore.ParseBundle(raw, "ML-KEM-1024"); !errors.Is(err, keystore.ErrCorruptedBundle) {
		t.Fatalf("algorithme différent : ErrCorruptedBundle attendu, obtenu %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-4] ^= 1 // dans le checksum
	if _, _, err := keystore.ParseBundle(tampered, ""); !errors.Is(err, keystore.ErrCorruptedBundle) {
		t.Fatalf("bundle altéré : ErrCorruptedBundle attendu, obtenu %v", err)
	}
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	src := &memStore{pk: []byte("pk"), sk: []byte("sk")}

	dst := &memStore{}
	if r, err := keystore.Migrate(ctx, src, dst); err != nil || r != keystore.MigrationCopied {
		t.Fatalf("copie : %v, %v", r, err)
	}
	if string(dst.pk) != "pk" || string(dst.sk) != "sk" {
		t.Fatal("paire copiée différente")
	}

	// Rejeu : la cible détient déjà la même paire, rien n'est réécrit.
	if r, err := keystore.Migrate(ctx, src, dst); err != nil || r != keystore.MigrationAlreadyPresent || dst.writes != 1 {
		t.Fatalf("rejeu : %v, %v, écritures=%d", r, err, dst.writes)
	}

	// Cible avec une autre paire : refus, rien n'est modifié.
	other := &memStore{pk: []byte("autre"), sk: []byte("autre-sk")}
	if _, err := keystore.Migrate(ctx, src, other); !errors.Is(err, keystore.ErrMigrationConflict) {
		t.Fatalf("conflit : ErrMigrationConflict attendu, obtenu %v", err)
	}
	if string(other.pk) != "autre" {
		t.Fatal("la cible ne doit pas être modifiée en cas de conflit")
	}

	// Source vide : erreur, la cible reste vide.
	empty, target := &memStore{}, &memStore{}
	if _, err := keystore.Migrate(ctx, empty, target); err == nil || target.pk != nil {
		t.Fatal("une source sans paire doit faire échouer la migration sans écrire")
	}
	if string(src.pk) != "pk" {
		t.Fatal("la source ne doit jamais être modifiée")
	}
}

func TestRegistry(t *testing.T) {
	keystore.Register(keystore.Backend{
		Name:       "Registry-Test",
		SecretVars: []string{"REGISTRY_TEST_SECRET"},
		Open:       func(keystore.Settings) (keystore.Store, error) { return &memStore{}, nil },
	})
	if _, err := keystore.Lookup("registry-test"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(keystore.Names(), "registry-test") {
		t.Fatal("coffre absent de Names()")
	}
	if !slices.Contains(keystore.AllSecretVars(), "REGISTRY_TEST_SECRET") {
		t.Fatal("variable secrète absente de AllSecretVars()")
	}
	if _, err := keystore.Lookup("inexistant"); err == nil {
		t.Fatal("un coffre inconnu doit être refusé")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("un double enregistrement doit paniquer")
		}
	}()
	keystore.Register(keystore.Backend{Name: "registry-test", Open: func(keystore.Settings) (keystore.Store, error) { return nil, nil }})
}

type closingStore struct {
	memStore
	closed bool
}

func (c *closingStore) Close() { c.closed = true }

// TestWithErasure vérifie que l'enveloppe d'effacement délègue sans rien changer au contrat.
func TestWithErasure(t *testing.T) {
	if keystore.WithErasure(nil) != nil {
		t.Fatal("WithErasure(nil) doit rester nil : pas de coffre")
	}
	inner := &closingStore{}
	s := keystore.WithErasure(inner)
	ctx := context.Background()
	if _, _, err := s.FetchKeys(ctx); !errors.Is(err, keystore.ErrSecretNotFound) {
		t.Fatalf("FetchKeys délégué : %v", err)
	}
	if err := s.StoreKeys(ctx, []byte("pk"), []byte("sk")); err != nil {
		t.Fatal(err)
	}
	if pk, sk, err := s.FetchKeys(ctx); err != nil || string(pk) != "pk" || string(sk) != "sk" {
		t.Fatalf("aller-retour sous effacement : %q %q %v", pk, sk, err)
	}
	s.(interface{ Close() }).Close()
	if !inner.closed {
		t.Fatal("Close doit être délégué")
	}
	if s.(interface{ Unwrap() keystore.Store }).Unwrap() != keystore.Store(inner) {
		t.Fatal("Unwrap doit renvoyer le coffre enveloppé")
	}
}

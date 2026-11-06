package config

import (
	"context"
	"os"
	"testing"

	"pq-crypto-service/internal/keystore"
)

const testKeystoreName = "testvault"

type nopStore struct{}

func (nopStore) FetchKeys(context.Context) ([]byte, []byte, error) {
	return nil, nil, keystore.ErrSecretNotFound
}
func (nopStore) StoreKeys(context.Context, []byte, []byte) error { return nil }

func init() {
	keystore.Register(keystore.Backend{
		Name:       testKeystoreName,
		SecretVars: []string{"TESTVAULT_SECRET"},
		Open:       func(keystore.Settings) (keystore.Store, error) { return nopStore{}, nil },
	})
}

// TestKeystore_SelectionAndSecrets vérifie la sélection du coffre et le transfert de ses
// secrets : lus au chargement, retirés de l'environnement, remis une seule fois au coffre,
// effacés par WipeSecrets.
func TestKeystore_SelectionAndSecrets(t *testing.T) {
	t.Setenv("KEYSTORE", "TestVault")
	t.Setenv("TESTVAULT_SECRET", "s3cr3t")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Keystore != testKeystoreName {
		t.Fatalf("Keystore = %q, attendu %q", cfg.Keystore, testKeystoreName)
	}
	if _, set := os.LookupEnv("TESTVAULT_SECRET"); set {
		t.Fatal("le secret du coffre doit être retiré de l'environnement")
	}
	settings := cfg.KeystoreSettings()
	if got := string(settings.Secret("TESTVAULT_SECRET")); got != "s3cr3t" {
		t.Fatalf("secret transmis = %q", got)
	}
	if settings.Secret("TESTVAULT_SECRET") != nil {
		t.Fatal("un secret ne se remet qu'une fois")
	}
	cfg.WipeSecrets()
}

// TestKeystore_InfisicalEnabledAlias vérifie la compatibilité de INFISICAL_ENABLED.
func TestKeystore_InfisicalEnabledAlias(t *testing.T) {
	for _, tc := range []struct {
		keystore, enabled, want string
		wantErr                 bool
	}{
		{"", "true", "infisical", false},
		{"infisical", "true", "infisical", false},
		{"openbao", "true", "", true},
		{"none", "false", "", false},
		{"", "", "", false},
	} {
		t.Setenv("KEYSTORE", tc.keystore)
		t.Setenv("INFISICAL_ENABLED", tc.enabled)
		got, err := resolveKeystore()
		if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
			t.Errorf("KEYSTORE=%q INFISICAL_ENABLED=%q : %q, %v", tc.keystore, tc.enabled, got, err)
		}
	}
}

// TestKeystore_UnknownRefusedAtLoad vérifie qu'un coffre inconnu fait échouer le chargement.
func TestKeystore_UnknownRefusedAtLoad(t *testing.T) {
	t.Setenv("KEYSTORE", "coffre-inexistant")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("un coffre inconnu doit être refusé au chargement")
	}
}

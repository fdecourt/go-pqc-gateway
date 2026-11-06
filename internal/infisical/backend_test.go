package infisical_test

import (
	"testing"

	"pq-crypto-service/internal/infisical"
	"pq-crypto-service/internal/keystore"
)

// TestOptionsValidate_HTTPSInProduction : la clé privée et le client_secret transitent vers
// Infisical, qui doit donc être joint en https en production.
func TestOptionsValidate_HTTPSInProduction(t *testing.T) {
	for _, tc := range []struct {
		url        string
		production bool
		wantErr    bool
	}{
		{"http://infisical:8080", true, true},
		{"https://infisical.example", true, false},
		{"http://infisical:8080", false, false},
	} {
		o := infisical.Options{URL: tc.url, BundleName: infisical.DefaultBundleName}
		if err := o.Validate(tc.production); (err != nil) != tc.wantErr {
			t.Errorf("URL=%s production=%v : erreur = %v", tc.url, tc.production, err)
		}
	}
	if err := (infisical.Options{URL: "https://x", BundleName: "../etc"}).Validate(true); err == nil {
		t.Error("un nom de bundle hors [A-Za-z0-9_.-] doit être refusé")
	}
}

func TestRegistered(t *testing.T) {
	if _, err := keystore.Lookup("infisical"); err != nil {
		t.Fatal(err)
	}
}

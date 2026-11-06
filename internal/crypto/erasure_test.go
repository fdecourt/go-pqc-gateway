//go:build goexperiment.runtimesecret

package crypto

import (
	"context"
	"runtime/secret"
	"testing"
)

// probeKEM enregistre si chaque appel KEM s'exécute sous runtime/secret.
type probeKEM struct {
	KEM
	encapProtected, decapProtected bool
}

func (p *probeKEM) Encapsulate(ctx context.Context, pk []byte) ([]byte, []byte, error) {
	p.encapProtected = secret.Enabled()
	return p.KEM.Encapsulate(ctx, pk)
}

func (p *probeKEM) Decapsulate(ctx context.Context, ct []byte) ([]byte, error) {
	p.decapProtected = secret.Enabled()
	return p.KEM.Decapsulate(ctx, ct)
}

func TestOperationsRunUnderSecretErasure(t *testing.T) {
	if !SecretErasure {
		t.Fatal("SecretErasure doit valoir true avec GOEXPERIMENT=runtimesecret")
	}
	s, err := LookupSuite("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	pk, sk, err := GenerateKeyPair(s.Name)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.FromKeys(pk, sk)
	if err != nil {
		t.Fatal(err)
	}
	probe := &probeKEM{KEM: k}
	e := newHybridEngine(probe, s)
	ctx := context.Background()

	sealed, err := e.Seal(ctx, []byte("clair"), nil, UsageDataEncryption, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := e.Open(ctx, sealed, UsageDataEncryption)
	if err != nil {
		t.Fatal(err)
	}
	Zeroize(pt)
	if !probe.encapProtected || !probe.decapProtected {
		t.Fatalf("Seal/Open hors runtime/secret (encap=%v, decap=%v)", probe.encapProtected, probe.decapProtected)
	}

	probe.encapProtected, probe.decapProtected = false, false
	res, err := e.Encapsulate(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := e.Decapsulate(ctx, res.EncapsulatedKey)
	if err != nil {
		t.Fatal(err)
	}
	Zeroize(ss)
	Zeroize(res.SharedSecret)
	if !probe.encapProtected || !probe.decapProtected {
		t.Fatal("Encapsulate/Decapsulate hors runtime/secret")
	}
	if secret.Enabled() {
		t.Fatal("le périmètre runtime/secret ne doit pas fuir hors de l'opération")
	}
}

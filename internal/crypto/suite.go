package crypto

import (
	"fmt"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

type SuiteID uint16

const (
	SuiteUnknown             SuiteID = 0x0000
	SuiteMLKEM768_AES256GCM  SuiteID = 0x0001
	SuiteMLKEM1024_AES256GCM SuiteID = 0x0002
	SuiteDual768_AES256GCM   SuiteID = 0x0003
	SuiteDual1024_AES256GCM  SuiteID = 0x0004
	SuiteMock                SuiteID = 0xFF00
)

// Suite décrit une suite cryptographique : son identité, la génération de sa paire de clés
// sérialisée et la construction d'un KEM à partir de cette paire. Générer des octets puis les
// charger est le seul chemin : le moteur n'a jamais à exporter sa clé privée.
type Suite struct {
	ID              SuiteID
	Name            string
	KEMName         string
	Aliases         []string
	GenerateKeyPair func() (pk, sk []byte, err error)
	FromKeys        func(pk, sk []byte) (KEM, error)
}

func mlkemSuite(id SuiteID, scheme kem.Scheme, kemName string) Suite {
	return Suite{
		ID: id, Name: kemName + "+AES-256-GCM", KEMName: kemName,
		GenerateKeyPair: func() ([]byte, []byte, error) { return generateMLKEMKeyPair(scheme, kemName) },
		FromKeys:        func(pk, sk []byte) (KEM, error) { return NewMLKEMWithKeys(scheme, kemName, pk, sk) },
	}
}

func dualSuite(id SuiteID, scheme kem.Scheme, kemName string, aliases ...string) Suite {
	return Suite{
		ID: id, Name: kemName + "+AES-256-GCM", KEMName: kemName, Aliases: aliases,
		GenerateKeyPair: func() ([]byte, []byte, error) { return generateDualKeyPair(scheme) },
		FromKeys:        func(pk, sk []byte) (KEM, error) { return NewDualHybridWithKeys(scheme, kemName, pk, sk) },
	}
}

var registry = []Suite{
	mlkemSuite(SuiteMLKEM768_AES256GCM, mlkem768.Scheme(), "ML-KEM-768"),
	mlkemSuite(SuiteMLKEM1024_AES256GCM, mlkem1024.Scheme(), "ML-KEM-1024"),
	dualSuite(SuiteDual768_AES256GCM, mlkem768.Scheme(), "DUAL-X25519+ML-KEM-768", "DUAL-HYBRID"),
	dualSuite(SuiteDual1024_AES256GCM, mlkem1024.Scheme(), "DUAL-X25519+ML-KEM-1024"),
	// La suite MOCK (SuiteMock) n'est enregistrée que par mock.go, compilé avec le tag "mock".
}

// LookupSuite résout une suite par son nom canonique, son nom de KEM ou un alias (insensible à la casse).
func LookupSuite(name string) (Suite, error) {
	trimmed := strings.TrimSpace(name)
	for _, s := range registry {
		if strings.EqualFold(s.Name, trimmed) || strings.EqualFold(s.KEMName, trimmed) {
			return s, nil
		}
		for _, alias := range s.Aliases {
			if strings.EqualFold(alias, trimmed) {
				return s, nil
			}
		}
	}
	return Suite{}, fmt.Errorf("%w: '%s'", ErrUnsupportedAlgorithm, name)
}

// GenerateKeyPair génère une paire de clés sérialisée pour la suite nommée.
// L'appelant est responsable d'effacer sk (Zeroize) après usage.
func GenerateKeyPair(name string) (pk, sk []byte, err error) {
	s, err := LookupSuite(name)
	if err != nil {
		return nil, nil, err
	}
	withSecretErasure(func() { pk, sk, err = s.GenerateKeyPair() })
	return pk, sk, err
}

// NewEngineWithKeys instancie un moteur à partir d'une paire de clés sérialisée.
// La paire est validée par un self-test avant d'être acceptée.
func NewEngineWithKeys(name string, pk, sk []byte) (Engine, error) {
	s, err := LookupSuite(name)
	if err != nil {
		return nil, err
	}
	var k KEM
	withSecretErasure(func() { k, err = s.FromKeys(pk, sk) })
	if err != nil {
		return nil, err
	}
	return newHybridEngine(k, s), nil
}

// NewEngineForSuite instancie un moteur avec une paire de clés fraîche, en mémoire vive uniquement.
func NewEngineForSuite(name string) (Engine, error) {
	pk, sk, err := GenerateKeyPair(name)
	if err != nil {
		return nil, err
	}
	defer Zeroize(sk)
	return NewEngineWithKeys(name, pk, sk)
}

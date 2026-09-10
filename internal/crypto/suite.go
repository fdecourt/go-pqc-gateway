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

type Suite struct {
	ID       SuiteID
	Name     string
	KEMName  string
	Aliases  []string
	Scheme   kem.Scheme
	New      func() (KEM, error)
	FromKeys func(pk, sk []byte) (KEM, error)
}

var registry = []Suite{
	{
		ID: SuiteMLKEM768_AES256GCM, Name: "ML-KEM-768+AES-256-GCM", KEMName: "ML-KEM-768",
		Scheme:   mlkem768.Scheme(),
		New:      func() (KEM, error) { return NewMLKEM(mlkem768.Scheme(), "ML-KEM-768") },
		FromKeys: func(pk, sk []byte) (KEM, error) { return NewMLKEMWithKeys(mlkem768.Scheme(), "ML-KEM-768", pk, sk) },
	},
	{
		ID: SuiteMLKEM1024_AES256GCM, Name: "ML-KEM-1024+AES-256-GCM", KEMName: "ML-KEM-1024",
		Scheme:   mlkem1024.Scheme(),
		New:      func() (KEM, error) { return NewMLKEM(mlkem1024.Scheme(), "ML-KEM-1024") },
		FromKeys: func(pk, sk []byte) (KEM, error) { return NewMLKEMWithKeys(mlkem1024.Scheme(), "ML-KEM-1024", pk, sk) },
	},
	{
		ID: SuiteDual768_AES256GCM, Name: "DUAL-X25519+ML-KEM-768+AES-256-GCM", KEMName: "DUAL-X25519+ML-KEM-768",
		Aliases: []string{"DUAL-HYBRID"},
		Scheme:  mlkem768.Scheme(),
		New:     func() (KEM, error) { return NewDualHybrid(mlkem768.Scheme(), "DUAL-X25519+ML-KEM-768") },
		FromKeys: func(pk, sk []byte) (KEM, error) {
			return NewDualHybridWithKeys(mlkem768.Scheme(), "DUAL-X25519+ML-KEM-768", pk, sk)
		},
	},
	{
		ID: SuiteDual1024_AES256GCM, Name: "DUAL-X25519+ML-KEM-1024+AES-256-GCM", KEMName: "DUAL-X25519+ML-KEM-1024",
		Scheme: mlkem1024.Scheme(),
		New:    func() (KEM, error) { return NewDualHybrid(mlkem1024.Scheme(), "DUAL-X25519+ML-KEM-1024") },
		FromKeys: func(pk, sk []byte) (KEM, error) {
			return NewDualHybridWithKeys(mlkem1024.Scheme(), "DUAL-X25519+ML-KEM-1024", pk, sk)
		},
	},
	{
		ID: SuiteMock, Name: "MOCK-ML-KEM-768+AES-256-GCM", KEMName: "MOCK-ML-KEM-768",
		Aliases:  []string{"MOCK"},
		Scheme:   mlkem768.Scheme(),
		New:      func() (KEM, error) { return NewMockKEM(), nil },
		FromKeys: func(pk, sk []byte) (KEM, error) { return NewMockKEM(), nil },
	},
}

// AllSuites retourne la liste des suites supportées.
// Réservé pour la future rotation dynamique de clés.
func AllSuites() []Suite {
	res := make([]Suite, len(registry))
	copy(res, registry)
	return res
}

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

// LookupSuiteByID résout une suite par son identifiant binaire uint16.
// Réservé pour la future rotation dynamique de clés.
func LookupSuiteByID(id SuiteID) (Suite, error) {
	for _, s := range registry {
		if s.ID == id {
			return s, nil
		}
	}
	return Suite{}, fmt.Errorf("%w: identifiant 0x%04X", ErrUnsupportedAlgorithm, uint16(id))
}

// NewEngineWithKeys instancie un moteur cryptographique à partir d'un algorithme et d'une paire de clés (strict par défaut).
func NewEngineWithKeys(name string, pk, sk []byte) (Engine, error) {
	return NewEngineWithKeysAndPolicy(name, pk, sk, false)
}

// NewEngineWithKeysAndPolicy instancie un moteur cryptographique avec contrôle explicite de la politique legacy.
func NewEngineWithKeysAndPolicy(name string, pk, sk []byte, allowLegacy bool) (Engine, error) {
	s, err := LookupSuite(name)
	if err != nil {
		return nil, err
	}
	var kem KEM
	if pk != nil && sk != nil {
		kem, err = s.FromKeys(pk, sk)
	} else {
		kem, err = s.New()
	}
	if err != nil {
		return nil, err
	}
	return newHybridEngine(kem, s, allowLegacy), nil
}

// NewEngineForSuite instancie un moteur cryptographique avec génération de clés fraîches en mémoire vive.
func NewEngineForSuite(name string) (Engine, error) {
	return NewEngineWithKeys(name, nil, nil)
}

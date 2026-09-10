package tests

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"

	servicecrypto "pq-crypto-service/internal/crypto"
)

// TestAuditMLKEMStandardLibraryInterop checks the service adapter against a
// separate ML-KEM implementation. These public fixtures are test material only.
// This checks valid key generation and both exchange directions, not certification.
func TestAuditMLKEMStandardLibraryInterop(t *testing.T) {
	testCases := []struct {
		name   string
		scheme kem.Scheme
		newGo  func([]byte) ([]byte, func() ([]byte, []byte), func([]byte) ([]byte, error), error)
	}{
		{
			name: "ML-KEM-768", scheme: mlkem768.Scheme(),
			newGo: func(seed []byte) ([]byte, func() ([]byte, []byte), func([]byte) ([]byte, error), error) {
				dk, err := mlkem.NewDecapsulationKey768(seed)
				if err != nil {
					return nil, nil, nil, err
				}
				ek := dk.EncapsulationKey()
				return ek.Bytes(), ek.Encapsulate, dk.Decapsulate, nil
			},
		},
		{
			name: "ML-KEM-1024", scheme: mlkem1024.Scheme(),
			newGo: func(seed []byte) ([]byte, func() ([]byte, []byte), func([]byte) ([]byte, error), error) {
				dk, err := mlkem.NewDecapsulationKey1024(seed)
				if err != nil {
					return nil, nil, nil, err
				}
				ek := dk.EncapsulationKey()
				return ek.Bytes(), ek.Encapsulate, dk.Decapsulate, nil
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 4; i++ {
				t.Run(fmt.Sprintf("fixture-%d", i), func(t *testing.T) {
					seed := sha512.Sum512([]byte(fmt.Sprintf("pq-service-public-interop-fixture/%s/%d", tc.name, i)))
					goPK, goEncapsulate, goDecapsulate, err := tc.newGo(seed[:])
					if err != nil {
						t.Fatal(err)
					}
					pk, sk := tc.scheme.DeriveKeyPair(seed[:])
					pkBytes, err := pk.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(pkBytes, goPK) {
						t.Fatal("public keys differ for the same seed")
					}
					skBytes, err := sk.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					defer servicecrypto.Zeroize(skBytes)
					adapter, err := servicecrypto.NewMLKEMWithKeys(tc.scheme, tc.name, pkBytes, skBytes)
					if err != nil {
						t.Fatal(err)
					}
					goSecret, goCiphertext := goEncapsulate()
					defer servicecrypto.Zeroize(goSecret)
					serviceSecret, err := adapter.Decapsulate(context.Background(), goCiphertext)
					if err != nil {
						t.Fatal(err)
					}
					defer servicecrypto.Zeroize(serviceSecret)
					if !bytes.Equal(goSecret, serviceSecret) {
						t.Fatal("Go-to-service shared secrets differ")
					}
					serviceCiphertext, expected, err := adapter.Encapsulate(context.Background(), goPK)
					if err != nil {
						t.Fatal(err)
					}
					defer servicecrypto.Zeroize(expected)
					actual, err := goDecapsulate(serviceCiphertext)
					if err != nil {
						t.Fatal(err)
					}
					defer servicecrypto.Zeroize(actual)
					if !bytes.Equal(expected, actual) {
						t.Fatal("service-to-Go shared secrets differ")
					}
				})
			}
		})
	}
}

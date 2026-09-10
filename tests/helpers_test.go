package tests

import (
	"pq-crypto-service/internal/crypto"

	"github.com/cloudflare/circl/kem/schemes"
)

var (
	testMLKEM768Scheme = schemes.ByName("ML-KEM-768")
)

func newMLKEMEngine() (crypto.Engine, error) {
	return crypto.NewEngineForSuite("ML-KEM-768")
}

func newMLKEM1024Engine() (crypto.Engine, error) {
	return crypto.NewEngineForSuite("ML-KEM-1024")
}

func newDualHybridEngine() (crypto.Engine, error) {
	return crypto.NewEngineForSuite("DUAL-X25519+ML-KEM-768")
}

func newDualHybridEngineWithKeys(pk, sk []byte) (crypto.Engine, error) {
	return crypto.NewEngineWithKeys("DUAL-X25519+ML-KEM-768", pk, sk)
}

func newDualHybrid1024Engine() (crypto.Engine, error) {
	return crypto.NewEngineForSuite("DUAL-X25519+ML-KEM-1024")
}

func newDualHybridKEM() (crypto.KEM, error) {
	return crypto.NewDualHybrid(testMLKEM768Scheme, "DUAL-X25519+ML-KEM-768")
}

func newMLKEM768WithKeys(pk, sk []byte) (crypto.KEM, error) {
	return crypto.NewMLKEMWithKeys(testMLKEM768Scheme, "ML-KEM-768", pk, sk)
}

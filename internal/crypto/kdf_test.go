package crypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestHKDF_MatchesStandardLibrary compare la dérivation sur pile à crypto/hkdf et crypto/hmac
// sur les vecteurs de la RFC 5869 et sur des entrées aléatoires de toutes tailles admises.
func TestHKDF_MatchesStandardLibrary(t *testing.T) {
	// RFC 5869, cas 1 (sortie tronquée à 32 octets : premier bloc d'Expand).
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
	var got [32]byte
	if err := hkdfSHA256Key(&got, ikm, salt, string(info)); err != nil || !bytes.Equal(got[:], want) {
		t.Fatalf("vecteur RFC 5869 : %x (%v)", got, err)
	}

	for i := 0; i < 2000; i++ {
		ikm := make([]byte, 1+i%192)
		salt := make([]byte, i%65)
		info := make([]byte, i%193)
		_, _ = rand.Read(ikm)
		_, _ = rand.Read(salt)
		_, _ = rand.Read(info)
		ref, err := hkdf.Key(sha256.New, ikm, salt, string(info), 32)
		if err != nil {
			t.Fatal(err)
		}
		if err := hkdfSHA256Key(&got, ikm, salt, string(info)); err != nil || !bytes.Equal(got[:], ref) {
			t.Fatalf("itération %d : divergence avec crypto/hkdf (%v)", i, err)
		}
		var mac [32]byte
		hmacSHA256(&mac, salt, ikm, info)
		h := hmac.New(sha256.New, salt)
		h.Write(ikm)
		h.Write(info)
		if !bytes.Equal(mac[:], h.Sum(nil)) {
			t.Fatalf("itération %d : HMAC divergent de crypto/hmac", i)
		}
	}
	if err := hkdfSHA256Key(&got, nil, salt, "x"); err == nil {
		t.Fatal("ikm vide doit être refusé")
	}
	if err := hkdfSHA256Key(&got, ikm, make([]byte, 65), "x"); err == nil {
		t.Fatal("sel de plus de 64 octets doit être refusé (il serait pré-haché)")
	}
}

func BenchmarkDeriveSecret_NoAlloc(b *testing.B) {
	e, err := NewEngineForSuite("ML-KEM-1024")
	if err != nil {
		b.Fatal(err)
	}
	h := e.(*HybridEngine)
	secret := make([]byte, 32)
	encap := make([]byte, 1568)
	b.ReportAllocs()
	var k [AES256KeySize]byte
	for i := 0; i < b.N; i++ {
		_ = h.deriveSecret(&k, secret, UsageDataEncryption, encap, h.localPK, nil)
	}
}

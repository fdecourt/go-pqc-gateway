package api

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzParseBinaryEnvelope teste la robustesse de l'arithmétique de bornes contre des entrées arbitraires ou malveillantes.
func FuzzParseBinaryEnvelope(f *testing.F) {
	// Corpus initial : données aléatoires, courtes, vides
	f.Add([]byte{}, false)
	f.Add([]byte{}, true)
	f.Add([]byte{0x00, 0x01}, false)
	f.Add([]byte{'P', 'Q', BinaryFormatV2}, false)

	// Corpus : enveloppe V2 valide synthétique
	var buf bytes.Buffer
	buf.Write([]byte{'P', 'Q', BinaryFormatV2})
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))  // suite ID
	_ = binary.Write(&buf, binary.BigEndian, uint16(32)) // key length
	buf.Write(bytes.Repeat([]byte{0xAA}, 32))            // encap key
	buf.Write(bytes.Repeat([]byte{0xBB}, 12))            // nonce
	buf.Write(bytes.Repeat([]byte{0xCC}, 32))            // ciphertext (>=16)
	f.Add(buf.Bytes(), false)
	f.Add(buf.Bytes(), true)

	// Corpus : enveloppe legacy V0 synthétique
	var bufLegacy bytes.Buffer
	_ = binary.Write(&bufLegacy, binary.BigEndian, uint16(32)) // key length
	bufLegacy.Write(bytes.Repeat([]byte{0xAA}, 32))            // encap key
	bufLegacy.Write(bytes.Repeat([]byte{0xBB}, 12))            // nonce
	bufLegacy.Write(bytes.Repeat([]byte{0xCC}, 32))            // ciphertext
	f.Add(bufLegacy.Bytes(), false)
	f.Add(bufLegacy.Bytes(), true)

	f.Fuzz(func(t *testing.T, data []byte, allowLegacy bool) {
		// parseBinaryEnvelope ne doit jamais paniquer sur aucune entrée arbitraire
		suiteID, encapKey, nonce, cipher, err := parseBinaryEnvelope(data, allowLegacy)
		if err == nil {
			if len(nonce) != 12 {
				t.Fatalf("nonce invalide: attendu 12, obtenu %d", len(nonce))
			}
			if len(cipher) < 16 {
				t.Fatalf("chiffré trop court pour AES-GCM (tag de 16 octets min): %d", len(cipher))
			}
			if !allowLegacy && (len(data) < 3 || data[0] != 'P' || data[1] != 'Q') {
				t.Fatalf("enveloppe non signée acceptée alors que allowLegacy est faux")
			}
			_ = suiteID
			_ = encapKey
		}
	})
}

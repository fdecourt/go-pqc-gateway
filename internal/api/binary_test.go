package api

import (
	"bytes"
	"encoding/binary"
	"net/http/httptest"
	"testing"

	"pq-crypto-service/internal/crypto"
)

// syntheticEnvelope construit une enveloppe binaire du format demandé (V2 sans kid, V3 avec).
func syntheticEnvelope(format byte, kid []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{'P', 'Q', format})
	_ = binary.Write(&buf, binary.BigEndian, uint16(1)) // suite ID
	if format == BinaryFormatV3 {
		buf.Write(kid)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint16(32)) // key length
	buf.Write(bytes.Repeat([]byte{0xAA}, 32))            // encap key
	buf.Write(bytes.Repeat([]byte{0xBB}, 12))            // nonce
	buf.Write(bytes.Repeat([]byte{0xCC}, 32))            // ciphertext (>=16)
	return buf.Bytes()
}

// TestBinaryEnvelope_V3Layout fige le format émis et vérifie que V2 (0.0.x) reste lisible.
func TestBinaryEnvelope_V3Layout(t *testing.T) {
	sealed := &crypto.SealedPayload{
		SuiteID:         crypto.SuiteMLKEM768_AES256GCM,
		KeyID:           "0102030405060708",
		EncapsulatedKey: bytes.Repeat([]byte{0xAA}, 32),
		Nonce:           bytes.Repeat([]byte{0xBB}, 12),
		Data:            bytes.Repeat([]byte{0xCC}, 32),
	}
	rr := httptest.NewRecorder()
	if err := writeBinaryEnvelope(rr, sealed); err != nil {
		t.Fatal(err)
	}
	want := syntheticEnvelope(BinaryFormatV3, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if !bytes.Equal(rr.Body.Bytes(), want) {
		t.Fatalf("format V3 inattendu:\n obtenu %x\nattendu %x", rr.Body.Bytes(), want)
	}

	env, err := parseBinaryEnvelope(want)
	if err != nil || env.KeyID != sealed.KeyID || env.SuiteID != 1 ||
		!bytes.Equal(env.EncapKey, sealed.EncapsulatedKey) || !bytes.Equal(env.Nonce, sealed.Nonce) || !bytes.Equal(env.Cipher, sealed.Data) {
		t.Fatalf("relecture V3 incohérente: %+v, %v", env, err)
	}

	envV2, err := parseBinaryEnvelope(syntheticEnvelope(BinaryFormatV2, nil))
	if err != nil || envV2.KeyID != "" || !bytes.Equal(envV2.EncapKey, sealed.EncapsulatedKey) {
		t.Fatalf("relecture V2 incohérente: %+v, %v", envV2, err)
	}

	sealed.KeyID = "pas-hexa"
	if err := writeBinaryEnvelope(httptest.NewRecorder(), sealed); err == nil {
		t.Fatal("kid invalide accepté à l'écriture")
	}
}

// FuzzParseBinaryEnvelope teste la robustesse de l'arithmétique de bornes contre des entrées arbitraires ou malveillantes.
func FuzzParseBinaryEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01})
	f.Add([]byte{'P', 'Q', BinaryFormatV2})
	f.Add([]byte{'P', 'Q', BinaryFormatV3})
	v2 := syntheticEnvelope(BinaryFormatV2, nil)
	f.Add(v2)
	f.Add(syntheticEnvelope(BinaryFormatV3, bytes.Repeat([]byte{0x11}, crypto.KeyIDSize)))
	f.Add(v2[5:]) // ancien format sans en-tête (refusé)

	f.Fuzz(func(t *testing.T, data []byte) {
		// parseBinaryEnvelope ne doit jamais paniquer sur aucune entrée arbitraire
		env, err := parseBinaryEnvelope(data)
		if err != nil {
			return
		}
		if len(data) < 3 || data[0] != 'P' || data[1] != 'Q' {
			t.Fatalf("enveloppe sans en-tête 'PQ' acceptée")
		}
		if (data[2] == BinaryFormatV3) != (len(env.KeyID) == 2*crypto.KeyIDSize) {
			t.Fatalf("kid incohérent avec la version %d: %q", data[2], env.KeyID)
		}
		if len(env.Nonce) != 12 {
			t.Fatalf("nonce invalide: attendu 12, obtenu %d", len(env.Nonce))
		}
		if len(env.Cipher) < 16 {
			t.Fatalf("chiffré trop court pour AES-GCM (tag de 16 octets min): %d", len(env.Cipher))
		}
	})
}

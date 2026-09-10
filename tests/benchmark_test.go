package tests

import (
	"context"
	"testing"

	"pq-crypto-service/internal/crypto"
)

func BenchmarkMLKEM_KeyGen(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := newMLKEMEngine()
		if err != nil {
			b.Fatalf("keygen failed: %v", err)
		}
	}
}

func BenchmarkMLKEM_HybridEncrypt(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte("Benchmark payload containing 1KB of simulated transactional business data 1234567890abcdefghijklmnopqrstuvwxyz")
	pk := engine.GetPublicKey()

	b.Run("LocalKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := crypto.Encrypt(ctx, engine, plaintext, nil)
			if err != nil {
				b.Fatalf("encrypt failed: %v", err)
			}
		}
	})

	b.Run("ExternalKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := crypto.Encrypt(ctx, engine, plaintext, pk)
			if err != nil {
				b.Fatalf("encrypt failed: %v", err)
			}
		}
	})
}

func BenchmarkMLKEM_HybridDecrypt(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte("Benchmark payload containing 1KB of simulated transactional business data 1234567890abcdefghijklmnopqrstuvwxyz")
	payload, err := crypto.Encrypt(ctx, engine, plaintext, nil)
	if err != nil {
		b.Fatalf("encrypt setup failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := crypto.Decrypt(ctx, engine, payload)
		if err != nil {
			b.Fatalf("decrypt failed: %v", err)
		}
	}
}

func BenchmarkMock_HybridRoundtrip(b *testing.B) {
	mock := crypto.NewMockEngine()
	ctx := context.Background()
	plaintext := []byte("Benchmark payload for mock")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		payload, err := crypto.Encrypt(ctx, mock, plaintext, nil)
		if err != nil {
			b.Fatalf("mock encrypt error: %v", err)
		}
		_, err = crypto.Decrypt(ctx, mock, payload)
		if err != nil {
			b.Fatalf("mock decrypt error: %v", err)
		}
	}
}

func BenchmarkEnvelope_WrapKey_AES256(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	dek := make([]byte, 32)
	pk := engine.GetPublicKey()

	b.Run("LocalKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := crypto.WrapKey(ctx, engine, dek, nil)
			if err != nil {
				b.Fatalf("wrap failed: %v", err)
			}
		}
	})

	b.Run("ExternalKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := crypto.WrapKey(ctx, engine, dek, pk)
			if err != nil {
				b.Fatalf("wrap failed: %v", err)
			}
		}
	})
}

func BenchmarkEnvelope_UnwrapKey_AES256(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	dek := make([]byte, 32)
	wrapped, err := crypto.WrapKey(ctx, engine, dek, nil)
	if err != nil {
		b.Fatalf("wrap setup failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := crypto.UnwrapKey(ctx, engine, wrapped.EncapsulatedKey, wrapped.Nonce, wrapped.Data)
		if err != nil {
			b.Fatalf("unwrap failed: %v", err)
		}
	}
}

func BenchmarkEnvelope_PureKEM_Encapsulate(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	pk := engine.GetPublicKey()

	b.Run("LocalKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := engine.Encapsulate(ctx, nil)
			if err != nil {
				b.Fatalf("encapsulate failed: %v", err)
			}
		}
	})

	b.Run("ExternalKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := engine.Encapsulate(ctx, pk)
			if err != nil {
				b.Fatalf("encapsulate failed: %v", err)
			}
		}
	})
}

func BenchmarkMLKEM_HybridEncrypt_1MB(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	payload1MB := make([]byte, 1024*1024)
	for i := range payload1MB {
		payload1MB[i] = byte(i % 256)
	}
	pk := engine.GetPublicKey()

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := crypto.Encrypt(ctx, engine, payload1MB, pk)
		if err != nil {
			b.Fatalf("encrypt failed: %v", err)
		}
	}
}

func BenchmarkMLKEM_HybridDecrypt_1MB(b *testing.B) {
	engine, err := newMLKEMEngine()
	if err != nil {
		b.Fatalf("engine init failed: %v", err)
	}

	ctx := context.Background()
	payload1MB := make([]byte, 1024*1024)
	for i := range payload1MB {
		payload1MB[i] = byte(i % 256)
	}
	enc, err := crypto.Encrypt(ctx, engine, payload1MB, nil)
	if err != nil {
		b.Fatalf("encrypt setup failed: %v", err)
	}

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := crypto.Decrypt(ctx, engine, enc)
		if err != nil {
			b.Fatalf("decrypt failed: %v", err)
		}
	}
}

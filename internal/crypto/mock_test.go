//go:build mock

package crypto_test

import (
	"context"
	"testing"

	"pq-crypto-service/internal/crypto"
)

// TestBuildEngine_MockRequiresExplicitAllowance vérifie que le mode simulé et la suite MOCK
// ne sont accessibles que si l'appelant l'autorise explicitement (hors production).
func TestBuildEngine_MockRequiresExplicitAllowance(t *testing.T) {
	ctx := context.Background()
	for _, opts := range []crypto.EngineOptions{
		{Algorithm: "ML-KEM-768", MockMode: true},
		{Algorithm: "MOCK"},
	} {
		if _, err := crypto.BuildEngine(ctx, opts, nil); err == nil {
			t.Fatalf("mock accepté sans AllowMock: %+v", opts)
		}
		opts.AllowMock = true
		eng, err := crypto.BuildEngine(ctx, opts, nil)
		if err != nil || !eng.IsMock() {
			t.Fatalf("mock refusé malgré AllowMock (%+v): %v", opts, err)
		}
	}
}

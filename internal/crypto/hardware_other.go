//go:build !amd64 && !arm64

package crypto

// HardwareAES vaut false sur les architectures sans accélération AES connue de ce service.
func HardwareAES() bool { return false }

package crypto

import (
	"runtime"
)

//go:noinline
func wipeMem(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b[0])
}

// Zeroize effectue un écrasement explicite au mieux (best-effort) de la tranche d'octets fournie.
// L'emploi d'une fonction non-inlinable (//go:noinline) et de runtime.KeepAlive réduit le risque
// d'élimination par le compilateur. Cela ne garantit pas l'élimination de copies éventuelles gérées par le runtime.
func Zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	wipeMem(b)
	runtime.KeepAlive(b)
}

package secmem

import "runtime"

//go:noinline
func wipeMem(b []byte) {
	clear(b)
	runtime.KeepAlive(&b[0])
}

// Wipe écrase b avec des zéros. La fonction non inlinable et runtime.KeepAlive empêchent le
// compilateur d'éliminer l'écriture comme « morte ». Wipe n'atteint pas les copies de b faites
// ailleurs : c'est à l'appelant de ne pas en créer.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	wipeMem(b)
	runtime.KeepAlive(b)
}

// WipeAll efface chaque tranche fournie.
func WipeAll(bs ...[]byte) {
	for _, b := range bs {
		Wipe(b)
	}
}

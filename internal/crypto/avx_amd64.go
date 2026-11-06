package crypto

import "golang.org/x/sys/cpu"

//go:noescape
func vzeroupper()

var hasAVX = cpu.X86.HasAVX

// clearUpperAVXState remet à zéro la moitié haute des registres YMM.
//
// L'assembleur AVX2 de circl (Keccak ×4) rend la main sans VZEROUPPER. Sur les CPU
// Intel depuis Skylake, chaque instruction SSE non-VEX exécutée ensuite — dont les
// blocs SHA-NI de crypto/sha256 — paie une fausse dépendance sur cet état « sale ».
// Mesuré : le transcript et HKDF devenaient ~10× plus lents juste après une
// encapsulation. À appeler après chaque opération circl.
func clearUpperAVXState() {
	if hasAVX {
		vzeroupper()
	}
}

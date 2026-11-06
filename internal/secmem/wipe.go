package secmem

import (
	"runtime"
	"unsafe"
)

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

// WipeString écrase les octets d'une chaîne qui contenait un secret et que plus rien ne lira.
//
// Réservé aux chaînes allouées à l'exécution dont l'appelant tient la seule référence utile,
// typiquement la valeur d'une variable d'environnement secrète lue par os.LookupEnv juste
// avant os.Unsetenv : le runtime Go recopie l'environnement dans le tas au lancement, avant
// tout code du service, et cette copie survivrait sinon à la variable. Ne jamais l'appeler sur
// un littéral (mémoire en lecture seule) ni sur une chaîne encore utilisée ailleurs : les
// chaînes Go sont immuables par contrat, et cette fonction rompt ce contrat délibérément.
func WipeString(s string) {
	if len(s) == 0 {
		return
	}
	Wipe(unsafe.Slice(unsafe.StringData(s), len(s)))
}

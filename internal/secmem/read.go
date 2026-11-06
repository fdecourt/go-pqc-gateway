package secmem

import (
	"errors"
	"io"
)

// ErrTooLarge signale un flux plus long que la limite autorisée.
var ErrTooLarge = errors.New("flux plus long que la limite autorisée")

// minReadChunk est la capacité initiale quand la taille annoncée est inconnue.
const minReadChunk = 512

// TailSlack est la capacité réservée au-delà des données lues : un chiffrement AES-GCM en
// place (clair remplacé par le chiffré et son étiquette de 16 octets) tient alors dans le
// tampon de la requête, sans réallocation ni copie du clair.
const TailSlack = 16

// ReadAll lit r jusqu'à EOF dans un tampon dont l'appelant devient propriétaire.
//
// Contrairement à io.ReadAll, chaque réallocation efface l'ancien tableau : aucune copie
// partielle du flux ne reste dans le tas. sizeHint (par exemple Content-Length, -1 si inconnu)
// dimensionne le tampon d'emblée ; il n'est pas cru au-delà de limit. Au-delà de limit octets,
// la lecture s'arrête, le tampon est effacé et ErrTooLarge est renvoyée. Toute erreur de r
// autre qu'EOF est renvoyée telle quelle, après effacement.
func ReadAll(r io.Reader, sizeHint, limit int64) ([]byte, error) {
	if limit < 0 {
		limit = 0
	}
	capacity := int64(minReadChunk)
	if sizeHint >= 0 && sizeHint <= limit {
		capacity = sizeHint + 1 // +1 : l'EOF se lit sans réallocation
	}
	capacity = min(capacity, limit+1)
	buf := NewBuffer(int(capacity) + TailSlack)

	for {
		// La fenêtre de lecture exclut TailSlack : il reste réservé au chiffrement en place.
		if buf.Len() == cap(buf.b)-TailSlack {
			buf.Grow(min(max(buf.Len(), minReadChunk), int(limit+1)-buf.Len()) + TailSlack)
		}
		n, err := r.Read(buf.b[len(buf.b) : cap(buf.b)-TailSlack])
		buf.b = buf.b[:len(buf.b)+n]
		if int64(buf.Len()) > limit {
			buf.Wipe()
			return nil, ErrTooLarge
		}
		if errors.Is(err, io.EOF) {
			return buf.b, nil
		}
		if err != nil {
			buf.Wipe()
			return nil, err
		}
	}
}

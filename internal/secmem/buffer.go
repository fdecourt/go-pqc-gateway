package secmem

import (
	"encoding/base64"
	"strconv"
)

// Buffer est un tampon d'octets qui efface son ancien stockage chaque fois qu'il grandit.
//
// append() sur une tranche ordinaire abandonne l'ancien tableau au ramasse-miettes avec son
// contenu : une réponse contenant un clair laisserait derrière elle autant de copies partielles
// que de réallocations. Buffer réserve la place exacte avant chaque écriture et efface
// l'ancien tableau quand il doit en changer. La valeur zéro est utilisable.
type Buffer struct {
	b []byte
}

// NewBuffer crée un tampon d'une capacité initiale donnée (idéalement la taille finale exacte).
func NewBuffer(capacity int) *Buffer {
	return &Buffer{b: make([]byte, 0, max(capacity, 0))}
}

// Grow garantit la place pour n octets supplémentaires sans réallocation ultérieure.
func (buf *Buffer) Grow(n int) {
	if n <= cap(buf.b)-len(buf.b) {
		return
	}
	newCap := max(2*cap(buf.b), len(buf.b)+n)
	nb := make([]byte, len(buf.b), newCap)
	copy(nb, buf.b)
	Wipe(buf.b[:cap(buf.b)])
	buf.b = nb
}

// Len renvoie le nombre d'octets écrits.
func (buf *Buffer) Len() int { return len(buf.b) }

// Bytes renvoie le contenu, sans copie. Il reste la propriété du Buffer (effacé par Wipe).
func (buf *Buffer) Bytes() []byte { return buf.b }

// Write implémente io.Writer.
func (buf *Buffer) Write(p []byte) (int, error) {
	buf.Grow(len(p))
	buf.b = append(buf.b, p...)
	return len(p), nil
}

// WriteString ajoute s.
func (buf *Buffer) WriteString(s string) {
	buf.Grow(len(s))
	buf.b = append(buf.b, s...)
}

// WriteByte ajoute c.
func (buf *Buffer) WriteByte(c byte) error {
	buf.Grow(1)
	buf.b = append(buf.b, c)
	return nil
}

// WriteBase64 ajoute l'encodage Base64 standard (RFC 4648, avec remplissage) de p,
// directement dans le tampon : aucune chaîne intermédiaire.
func (buf *Buffer) WriteBase64(p []byte) {
	n := base64.StdEncoding.EncodedLen(len(p))
	buf.Grow(n)
	start := len(buf.b)
	buf.b = buf.b[:start+n]
	base64.StdEncoding.Encode(buf.b[start:], p)
}

// WriteUint ajoute la représentation décimale de v.
func (buf *Buffer) WriteUint(v uint64) {
	var tmp [20]byte
	buf.Write(strconv.AppendUint(tmp[:0], v, 10))
}

// WriteInt ajoute la représentation décimale de v.
func (buf *Buffer) WriteInt(v int64) {
	var tmp [20]byte
	buf.Write(strconv.AppendInt(tmp[:0], v, 10))
}

// Wipe efface tout le stockage (y compris la capacité non utilisée) et vide le tampon.
func (buf *Buffer) Wipe() {
	Wipe(buf.b[:cap(buf.b)])
	buf.b = buf.b[:0]
}

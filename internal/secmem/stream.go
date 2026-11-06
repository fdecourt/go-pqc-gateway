package secmem

import (
	"encoding/base64"
	"io"
	"sync"
	"unicode/utf8"
)

// streamChunk est la taille des blocs d'entrée des écritures en flux : 48 Kio donnent 64 Kio
// de Base64, un multiple de 3 qui n'introduit aucun remplissage intermédiaire.
const streamChunk = 48 << 10

// Les tampons de flux sont passés à un io.Writer (interface) : le compilateur ne peut pas les
// garder sur la pile. Ils viennent d'un pool et y retournent effacés sur la partie utilisée,
// de sorte qu'aucun octet de la réponse précédente n'y subsiste.
var (
	base64Chunks = sync.Pool{New: func() any { return new([streamChunk / 3 * 4]byte) }}
	escapeChunks = sync.Pool{New: func() any { return new([6 * streamChunk]byte) }} // pire cas : \u00XX par octet
)

// StreamBase64 écrit l'encodage Base64 standard de p dans w, par blocs : aucune copie
// intégrale de p ni de son encodage n'est allouée.
func StreamBase64(w io.Writer, p []byte) error {
	out := base64Chunks.Get().(*[streamChunk / 3 * 4]byte)
	defer base64Chunks.Put(out)
	for len(p) > 0 {
		n := min(len(p), streamChunk)
		m := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(out[:m], p[:n])
		_, err := w.Write(out[:m])
		Wipe(out[:m])
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// StreamJSONString écrit s en chaîne JSON (guillemets compris) dans w, par blocs échappés.
// s doit être de l'UTF-8 valide. L'encodage est celui de WriteJSONString, et la longueur
// totale celle de JSONStringLen.
func StreamJSONString(w io.Writer, s []byte) error {
	out := escapeChunks.Get().(*[6 * streamChunk]byte)
	defer escapeChunks.Put(out)
	if _, err := w.Write(quote); err != nil {
		return err
	}
	for len(s) > 0 {
		n := min(len(s), streamChunk)
		// Ne pas couper une séquence UTF-8 : reculer jusqu'à un début de rune.
		for n < len(s) && !utf8.RuneStart(s[n]) {
			n--
		}
		m := appendJSONEscaped(out[:0], s[:n])
		_, err := w.Write(m)
		Wipe(m)
		if err != nil {
			return err
		}
		s = s[n:]
	}
	_, err := w.Write(quote)
	return err
}

var quote = []byte{'"'}

// appendJSONEscaped ajoute à dst l'échappement JSON de s (sans guillemets).
func appendJSONEscaped(dst, s []byte) []byte {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch jsonEscapeLen(c) {
			case 1:
				dst = append(dst, c)
			case 2:
				dst = append(dst, '\\', shortEscape(c))
			default:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(s[i:])
		if r == ' ' || r == ' ' {
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
		} else {
			dst = append(dst, s[i:i+size]...)
		}
		i += size
	}
	return dst
}

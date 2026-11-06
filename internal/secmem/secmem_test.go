package secmem

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	Wipe(b)
	if !allZero(b) {
		t.Fatalf("Wipe n'a pas effacé: %q", b)
	}
	Wipe(nil) // ne doit pas paniquer
}

func TestBuffer_GrowWipesOldStorage(t *testing.T) {
	buf := NewBuffer(4)
	buf.WriteString("abcd")
	old := buf.b[:cap(buf.b)]
	buf.WriteString("efgh") // force une réallocation
	if !allZero(old) {
		t.Fatalf("l'ancien stockage n'a pas été effacé: %q", old)
	}
	if got := string(buf.Bytes()); got != "abcdefgh" {
		t.Fatalf("contenu inattendu: %q", got)
	}
	all := buf.b[:cap(buf.b)]
	buf.Wipe()
	if !allZero(all) || buf.Len() != 0 {
		t.Fatal("Wipe doit effacer toute la capacité et vider le tampon")
	}
}

func TestBuffer_Base64AndInts(t *testing.T) {
	var buf Buffer
	buf.WriteBase64([]byte{0xff, 0x00, 0x10})
	_ = buf.WriteByte(' ')
	buf.WriteUint(42)
	_ = buf.WriteByte(' ')
	buf.WriteInt(-7)
	if got := string(buf.Bytes()); got != "/wAQ 42 -7" {
		t.Fatalf("obtenu %q", got)
	}
}

// chunkReader renvoie au plus n octets par Read, pour exercer la croissance du tampon.
type chunkReader struct {
	r io.Reader
	n int
}

func (c chunkReader) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}

func TestReadAll(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 1000)
	for _, hint := range []int64{-1, 0, 10, int64(len(data)), int64(len(data)) * 10} {
		got, err := ReadAll(chunkReader{bytes.NewReader(data), 333}, hint, int64(len(data)))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("hint=%d: err=%v, égal=%v", hint, err, bytes.Equal(got, data))
		}
	}
	if _, err := ReadAll(bytes.NewReader(data), -1, int64(len(data))-1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("attendu ErrTooLarge, obtenu %v", err)
	}
	boom := errors.New("boom")
	if _, err := ReadAll(io.MultiReader(bytes.NewReader(data[:10]), iotestErr{boom}), -1, 100); !errors.Is(err, boom) {
		t.Fatalf("attendu l'erreur du lecteur, obtenu %v", err)
	}
	if got, err := ReadAll(strings.NewReader(""), 0, 0); err != nil || len(got) != 0 {
		t.Fatalf("flux vide: %v %q", err, got)
	}
}

type iotestErr struct{ err error }

func (e iotestErr) Read([]byte) (int, error) { return 0, e.err }

func TestWriteJSONString_MatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{"", "plain", "quote\" back\\slash", "ctl\x00\x01\x1f\n\r\t", "<script>&", "é€😀", "line sep ", "\x7f"} {
		assertJSONStringParity(t, s)
	}
}

func FuzzWriteJSONString(f *testing.F) {
	f.Add("a\"b\\c\n<>& é")
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip()
		}
		assertJSONStringParity(t, s)
	})
}

func assertJSONStringParity(t *testing.T, s string) {
	t.Helper()
	var buf Buffer
	buf.WriteJSONString([]byte(s))
	want, _ := json.Marshal(s)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("%q: obtenu %s, encoding/json %s", s, buf.Bytes(), want)
	}
	if JSONStringLen([]byte(s)) != len(want) {
		t.Fatalf("%q: JSONStringLen=%d, attendu %d", s, JSONStringLen([]byte(s)), len(want))
	}
}

func TestJSONObject(t *testing.T) {
	o := NewJSONObject(0)
	o.String("algorithm", "ML-KEM")
	o.StringOmitEmpty("kid", "")
	o.UintOmitZero("suite_id", 0)
	o.Uint("n", 3)
	o.Int("neg", -1)
	o.Text("plaintext", []byte("a\"b"))
	o.Base64("data", []byte{1, 2, 3})
	buf := o.FinishLine()
	defer buf.Wipe()
	want := `{"algorithm":"ML-KEM","n":3,"neg":-1,"plaintext":"a\"b","data":"AQID"}` + "\n"
	if got := string(buf.Bytes()); got != want {
		t.Fatalf("obtenu %s, attendu %s", got, want)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("JSON invalide")
	}
}

type inner struct {
	Ctx string `json:"context,omitempty"`
}

type sample struct {
	inner
	Data   Base64 `json:"data"`
	Note   Text   `json:"note"`
	N      int    `json:"n"`
	Hidden string `json:"-"`
}

func TestDecodeStrict_Accepts(t *testing.T) {
	data := []byte(` {"context":"x","data":"AQID","note":"h\u00e9","n":2} `)
	var s sample
	if err := DecodeStrict(data, &s, false); err != nil {
		t.Fatal(err)
	}
	if s.Ctx != "x" || !bytes.Equal(s.Data, []byte{1, 2, 3}) || string(s.Note) != "hé" || s.N != 2 {
		t.Fatalf("décodage inattendu: %+v", s)
	}
	// Les valeurs secrètes ont été effacées dans le tampon source.
	if bytes.Contains(data, []byte("AQID")) {
		t.Fatalf("le Base64 source n'a pas été effacé: %s", data)
	}
	var empty sample
	if err := DecodeStrict([]byte(" \n"), &empty, true); err != nil {
		t.Fatalf("corps vide autorisé: %v", err)
	}
	var null sample
	if err := DecodeStrict([]byte(`{"data":null}`), &null, false); err != nil || null.Data != nil {
		t.Fatalf("null doit laisser le champ vide: %v %v", err, null.Data)
	}
}

func TestDecodeStrict_Rejects(t *testing.T) {
	cases := map[string]string{
		"vide":              ``,
		"syntaxe":           `{"n":`,
		"tableau":           `[1]`,
		"inconnu":           `{"nope":1}`,
		"casse":             `{"Data":"AQID"}`,
		"doublon":           `{"n":1,"n":2}`,
		"clé échappée":      `{"d\u0061ta":"AQID"}`,
		"second document":   `{"n":1}{"n":2}`,
		"données après":     `{"n":1} x`,
		"base64 invalide":   `{"data":"@@@@"}`,
		"base64 non strict": `{"data":"AQJ="}`,
		"type":              `{"n":"deux"}`,
		"champ masqué":      `{"Hidden":"x"}`,
	}
	for name, in := range cases {
		var s sample
		if err := DecodeStrict([]byte(in), &s, false); err == nil {
			t.Errorf("%s: %s aurait dû être refusé", name, in)
		}
	}
}

func TestDecodeStrict_ErrorsNeverQuoteValues(t *testing.T) {
	var s sample
	err := DecodeStrict([]byte(`{"n":"TOPSECRET"}`), &s, false)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("l'erreur ne doit pas citer la valeur: %v", err)
	}
}

// FuzzDecodeStrict compare le décodeur à encoding/json : il ne doit jamais paniquer, jamais
// accepter ce qu'encoding/json refuse syntaxiquement, et, quand les deux acceptent, produire
// les mêmes valeurs.
func FuzzDecodeStrict(f *testing.F) {
	f.Add([]byte(`{"context":"x","data":"AQID","note":"n","n":2}`))
	f.Add([]byte(`{"a":[{"b":"}"}],"n":1}`))
	f.Add([]byte(`{"note":"\u00e9\ud83d\ude00\n\"","n":-0}`))
	f.Add([]byte(` {"n":12} `))
	f.Fuzz(func(t *testing.T, data []byte) {
		var ours sample
		err := DecodeStrict(append([]byte(nil), data...), &ours, false)

		type ref struct {
			Ctx  string `json:"context"`
			Data string `json:"data"`
			Note string `json:"note"`
			N    int    `json:"n"`
		}
		var theirs ref
		refErr := json.Unmarshal(data, &theirs)
		if err == nil && refErr != nil {
			t.Fatalf("accepté par DecodeStrict mais refusé par encoding/json: %q (%v)", data, refErr)
		}
		if err != nil {
			return
		}
		if ours.Ctx != theirs.Ctx || string(ours.Note) != theirs.Note || ours.N != theirs.N {
			t.Fatalf("valeurs différentes pour %q: %+v vs %+v", data, ours, theirs)
		}
		if theirs.Data != "" {
			want, derr := base64.StdEncoding.Strict().DecodeString(theirs.Data)
			if derr != nil || !bytes.Equal(ours.Data, want) {
				t.Fatalf("Base64 différent pour %q", data)
			}
		}
	})
}

func TestStreamBase64AndJSONString(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 47, 48 << 10, 48<<10 + 1, 150<<10 + 7} {
		p := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, n/4+1)[:n]
		var out bytes.Buffer
		if err := StreamBase64(&out, p); err != nil {
			t.Fatal(err)
		}
		if out.String() != base64.StdEncoding.EncodeToString(p) {
			t.Fatalf("n=%d: Base64 en flux différent", n)
		}
	}
	text := []byte(strings.Repeat("a\"b\\c\né€😀 ", 10000))
	var out bytes.Buffer
	if err := StreamJSONString(&out, text); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(string(text))
	if !bytes.Equal(out.Bytes(), want) || out.Len() != JSONStringLen(text) {
		t.Fatal("chaîne JSON en flux différente d'encoding/json")
	}
}

func TestReadAll_ReservesTailSlack(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	for _, hint := range []int64{-1, 1000} {
		got, err := ReadAll(chunkReader{bytes.NewReader(data), 7}, hint, 2000)
		if err != nil || cap(got)-len(got) < TailSlack {
			t.Fatalf("hint=%d: err=%v, marge=%d", hint, err, cap(got)-len(got))
		}
	}
}

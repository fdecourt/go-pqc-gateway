package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCgroupLimit(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		files []string
		want  int64
	}{
		{[]string{write("v2", "1073741824\n")}, 1 << 30},
		{[]string{write("max", "max\n")}, 0},
		{[]string{write("v1", "9223372036854771712\n")}, 0},
		{[]string{filepath.Join(dir, "absent"), write("fallback", "536870912")}, 512 << 20},
		{[]string{filepath.Join(dir, "absent")}, 0},
	}
	for _, c := range cases {
		if got := readCgroupLimit(c.files); got != c.want {
			t.Errorf("%v: obtenu %d, attendu %d", c.files, got, c.want)
		}
	}
}

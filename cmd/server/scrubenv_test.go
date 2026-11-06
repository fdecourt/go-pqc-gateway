package main

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// TestScrubEnviron relance le binaire de test avec un secret dans l'environnement et vérifie
// que, après scrubEnviron, /proc/self/environ ne le contient plus.
func TestScrubEnviron(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("spécifique à Linux")
	}
	if os.Getenv("SCRUB_HELPER") == "1" {
		const secret = "SECRET-VALUE-TO-SCRUB-0123456789"
		before, _ := os.ReadFile("/proc/self/environ")
		if !bytes.Contains(before, []byte(secret)) {
			t.Fatal("précondition : le secret doit être dans l'environnement initial")
		}
		if err := scrubEnviron("SCRUB_TARGET", "SCRUB_OTHER"); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile("/proc/self/environ")
		if bytes.Contains(after, []byte(secret)) {
			t.Fatal("le secret est encore dans /proc/self/environ")
		}
		if !bytes.Contains(after, []byte("SCRUB_TARGET=")) || !bytes.Contains(after, []byte("SCRUB_KEEP=visible")) {
			t.Fatal("seule la valeur doit être effacée, les autres variables restent intactes")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestScrubEnviron$", "-test.v")
	cmd.Env = append(os.Environ(), "SCRUB_HELPER=1", "SCRUB_TARGET=SECRET-VALUE-TO-SCRUB-0123456789", "SCRUB_KEEP=visible", "SCRUB_OTHER=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sous-processus: %v\n%s", err, out)
	}
}

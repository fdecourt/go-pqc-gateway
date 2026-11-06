package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLimitListener_BoundsConcurrentConnections(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(raw, 2)
	defer ln.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2, c3 := dial(), dial(), dial()
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()
	first, second := <-accepted, <-accepted
	select {
	case <-accepted:
		t.Fatal("une troisième connexion a été acceptée au-delà de la limite")
	case <-time.After(200 * time.Millisecond):
	}
	first.Close()
	select {
	case third := <-accepted:
		third.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("la troisième connexion n'a pas été acceptée après libération d'un créneau")
	}
	second.Close()
}

func TestPeerCredListener_RejectsOtherUIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq.sock")
	raw, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid())
	other := me + 1
	ln, err := newPeerCredListener(raw, []uint32{other})
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Le pair (nous) n'est pas dans la liste : la connexion est fermée côté serveur.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("la connexion d'un UID non admis aurait dû être fermée")
	}
	select {
	case <-accepted:
		t.Fatal("connexion acceptée malgré un UID non admis")
	default:
	}
}

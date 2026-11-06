//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"

	"pq-crypto-service/internal/api"
)

// peerCredListener n'accepte, sur un socket Unix, que les connexions dont le pair appartient
// à une liste d'UID (SO_PEERCRED, attesté par le noyau) ; les autres sont fermées avant la
// moindre lecture. L'UID est attaché à la connexion pour servir d'identité.
type peerCredListener struct {
	net.Listener
	allowed []uint32
}

func newPeerCredListener(ln net.Listener, allowed []uint32) (net.Listener, error) {
	if len(allowed) == 0 {
		return ln, nil
	}
	return &peerCredListener{Listener: ln, allowed: allowed}, nil
}

func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err != nil || !slices.Contains(l.allowed, uid) {
			slog.Warn("unix_peer_rejected", slog.Any("uid", uid), slog.Any("error", err))
			_ = c.Close()
			continue
		}
		return &peerConn{Conn: c, uid: uid}, nil
	}
}

// peerUID lit l'UID du pair d'une connexion Unix (SO_PEERCRED).
func peerUID(c net.Conn) (uint32, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("connexion sans descripteur")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

// peerConn porte l'UID vérifié du pair.
type peerConn struct {
	net.Conn
	uid uint32
}

// connContext attache l'UID du pair au contexte des requêtes de la connexion (http.Server.ConnContext).
func connContext(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*peerConn); ok {
		return api.ContextWithPeerUID(ctx, pc.uid)
	}
	if lc, ok := c.(*limitConn); ok {
		if pc, ok := lc.Conn.(*peerConn); ok {
			return api.ContextWithPeerUID(ctx, pc.uid)
		}
	}
	return ctx
}

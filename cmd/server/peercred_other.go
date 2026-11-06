//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
)

func newPeerCredListener(ln net.Listener, allowed []uint32) (net.Listener, error) {
	if len(allowed) > 0 {
		return nil, errPeerCredUnsupported
	}
	return ln, nil
}

// connContext : pas d'identité de pair hors Linux.
func connContext(ctx context.Context, c net.Conn) context.Context { return ctx }

var errPeerCredUnsupported = errors.New("SOCKET_ALLOWED_UIDS n'est pris en charge que sous Linux")

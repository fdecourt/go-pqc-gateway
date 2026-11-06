package main

import (
	"net"
	"sync"
)

// limitListener borne le nombre de connexions simultanées acceptées : au-delà, Accept attend
// qu'une connexion se ferme. Les goroutines et tampons par connexion (lecture d'en-têtes,
// poignée de main TLS) restent ainsi bornés face à un flot de connexions, sans que le reste
// du service ait à s'en protéger.
type limitListener struct {
	net.Listener
	slots chan struct{}
	once  sync.Once
	done  chan struct{}
}

func newLimitListener(ln net.Listener, limit int) net.Listener {
	if limit <= 0 {
		return ln
	}
	return &limitListener{Listener: ln, slots: make(chan struct{}, limit), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

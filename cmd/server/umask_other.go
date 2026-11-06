//go:build !unix

package main

// withSocketUmask est sans objet hors Unix : la création n'est pas restreinte par un umask.
func withSocketUmask(_ uint32, create func() error) error { return create() }

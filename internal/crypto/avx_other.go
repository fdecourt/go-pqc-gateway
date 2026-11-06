//go:build !amd64

package crypto

// clearUpperAVXState est sans objet hors amd64.
func clearUpperAVXState() {}

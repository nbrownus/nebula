package v2

import (
	"crypto/rsa"
	"time"
)

type NebulaCAPool struct {
	CAs           map[string]*Certificate
	certBlocklist map[string]struct{}
}

func (p *NebulaCAPool) VerifyCertificate(t time.Time, details []byte, publicKey []byte, signature []byte) error {
	panic("TODO")
}

func (p *NebulaCAPool) IsBlocklisted(pubkey *rsa.PublicKey) error {
	panic("TODO")
}

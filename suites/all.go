package suites

import (
	"go.dedis.ch/kyber/v3/group/curve25519"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/group/p256"
	"go.dedis.ch/kyber/v3/group/twisted"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func init() {
	// Those are variable time suites that shouldn't be used
	// in production environment when possible
	register(p256.NewBlakeSHA256P256())
	register(p256.NewBlakeSHA256QR512())
	register(bn256.NewSuiteG1())
	register(bn256.NewSuiteG2())
	register(bn256.NewSuiteGT())
	register(pairing.NewSuiteBn256())
	register(twisted.NewBlakeSHA256Curve1174(false))
	register(twisted.NewBlakeSHA256Curve41417(false))
	register(twisted.NewBlakeSHA256E382(false))
	register(twisted.NewBlakeSHA256E521(false))
	register(twisted.NewBlakeSHA256Twisted25519(false))
	// This is a constant time implementation that should be
	// used as much as possible
	register(edwards25519.NewBlakeSHA256Ed25519())
	register(curve25519.NewBlakeSHA256Curve25519())
}

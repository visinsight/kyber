package curve25519

import "go.dedis.ch/kyber/v3"

type Curve25519 struct{}

// Return the name of the curve, "Ed25519".
func (c *Curve25519) String() string {
	return "Ed25519"
}

// ScalarLen returns 32, the size in bytes of an encoded Scalar
// for the Ed25519 curve.
func (c *Curve25519) ScalarLen() int {
	return 32
}

// Scalar creates a new Scalar for the prime-order subgroup of the Ed25519 curve.
// The scalars in this package implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a little-endian integer, in order to remain
// compatible with other Ed25519 implementations, and with the standard implementation
// of the EdDSA signature.
func (c *Curve25519) Scalar() kyber.Scalar {
	return &scalar{}
}

// PointLen returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
func (c *Curve25519) PointLen() int {
	return 32
}

// Point creates a new Point on the Ed25519 curve.
func (c *Curve25519) Point() kyber.Point {
	return &point{}
}

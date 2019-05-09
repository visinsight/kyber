package curve25519

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"go.dedis.ch/fixbuf"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/internal/marshalling"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// SuiteCurve25519 is the basic suite for the twisted curves
type SuiteCurve25519 struct {
	Curve25519
}

// Hash returns the instance associated with the suite
func (s *SuiteCurve25519) Hash() hash.Hash {
	return sha256.New()
}

// XOF creates the XOF associated with the suite
func (s *SuiteCurve25519) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s *SuiteCurve25519) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *SuiteCurve25519) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.encoding interface
func (s *SuiteCurve25519) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteCurve25519) RandomStream() cipher.Stream {
	return random.New()
}

// NewBlakeSHA256Curve25519 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and Curve25519 in
// Montgomery representation.
func NewBlakeSHA256Curve25519() *SuiteCurve25519 {
	suite := new(SuiteCurve25519)
	return suite
}

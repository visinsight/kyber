package p256

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

// SuiteP256 is the suite for P256 curve
type SuiteP256 struct {
	p256
}

// Hash returns the instance associated with the suite
func (s *SuiteP256) Hash() hash.Hash {
	return sha256.New()
}

// XOF creates the XOF associated with the suite
func (s *SuiteP256) XOF(key []byte) kyber.XOF {
	return blake2xb.New(key)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteP256) RandomStream() cipher.Stream {
	return random.New()
}

func (s *SuiteP256) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *SuiteP256) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.encoding interface
func (s *SuiteP256) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// NewBlakeSHA256P256 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the NIST P-256
// elliptic curve. It returns random streams from Go's crypto/rand.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256P256() *SuiteP256 {
	suite := new(SuiteP256)
	suite.p256.Init()
	return suite
}

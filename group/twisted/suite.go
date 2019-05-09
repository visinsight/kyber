package twisted

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

// SuiteTwisted is the basic suite for the twisted curves
type SuiteTwisted struct {
	ProjectiveCurve
}

// Hash returns the instance associated with the suite
func (s *SuiteTwisted) Hash() hash.Hash {
	return sha256.New()
}

// XOF creates the XOF associated with the suite
func (s *SuiteTwisted) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s *SuiteTwisted) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *SuiteTwisted) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.encoding interface
func (s *SuiteTwisted) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteTwisted) RandomStream() cipher.Stream {
	return random.New()
}

// NewBlakeSHA256Twisted25519 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and Twisted25519.
//
// If fullGroup is false, then the group is the prime-order subgroup.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256Twisted25519(fullGroup bool) *SuiteTwisted {
	suite := new(SuiteTwisted)
	suite.Init(Param25519(), fullGroup)
	return suite
}

// NewBlakeSHA256Curve1174 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and Curve1174.
//
// If fullGroup is false, then the group is the prime-order subgroup.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256Curve1174(fullGroup bool) *SuiteTwisted {
	suite := new(SuiteTwisted)
	suite.Init(Param1174(), fullGroup)
	return suite
}

// NewBlakeSHA256E382 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and E382.
//
// If fullGroup is false, then the group is the prime-order subgroup.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256E382(fullGroup bool) *SuiteTwisted {
	suite := new(SuiteTwisted)
	suite.Init(ParamE382(), fullGroup)
	return suite
}

// NewBlakeSHA256E521 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and E521.
//
// If fullGroup is false, then the group is the prime-order subgroup.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256E521(fullGroup bool) *SuiteTwisted {
	suite := new(SuiteTwisted)
	suite.Init(ParamE521(), fullGroup)
	return suite
}

// NewBlakeSHA256Curve41417 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and Curve41417.
//
// If fullGroup is false, then the group is the prime-order subgroup.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's big.Int type.
func NewBlakeSHA256Curve41417(fullGroup bool) *SuiteTwisted {
	suite := new(SuiteTwisted)
	suite.Init(Param41417(), fullGroup)
	return suite
}

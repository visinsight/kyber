package curve25519

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v3/group/internal/marshalling"

	"go.dedis.ch/kyber/v3"
)

type scalar struct {
	fieldElement
}

func (s scalar) MarshalBinary() (data []byte, err error) {
	out := [32]byte{}
	var fe fieldElement
	fe = s.fieldElement
	feToBytes(&out, &fe)
	return out[:], nil
}

func (s *scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return errors.New("need 32 bytes for unmarshalling")
	}
	var src [32]byte
	copy(src[:], data)
	feFromBytes(&s.fieldElement, &src)
	return nil
}

// String returns the human readable string representation of the object.
func (s scalar) String() string {
	b, err := s.MarshalBinary()
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%x", b)
}

// Encoded length of this object in bytes.
func (s scalar) MarshalSize() int {
	return 32
}

// Encode the contents of this object and write it to an io.Writer.
func (s scalar) MarshalTo(w io.Writer) (int, error) {
	return marshalling.ScalarMarshalTo(&s, w)
}

// Decode the content of this object by reading from an io.Reader.
// If r is an XOF, it uses r to pick a valid object pseudo-randomly,
// which may entail reading more than Len bytes due to retries.
func (s *scalar) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.ScalarUnmarshalFrom(s, r)
}

// Equality test for two Scalars derived from the same Group.
func (s scalar) Equal(s2 kyber.Scalar) bool {
	s2fe, ok := s2.(*scalar)
	if !ok {
		return false
	}
	return s.fieldElement == s2fe.fieldElement
}

// Set sets the receiver equal to another Scalar a.
func (s *scalar) Set(a kyber.Scalar) kyber.Scalar {
	s.fieldElement = a.(*scalar).fieldElement
	return s
}

// Clone creates a new Scalar with the same value.
func (s *scalar) Clone() kyber.Scalar {
	c := &scalar{}
	c.fieldElement = s.fieldElement
	return c
}

// SetInt64 sets the receiver to a small integer value.
func (s *scalar) SetInt64(v int64) kyber.Scalar {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(v))
	s.SetBytes(buf[:])
	return s
}

// Set to the additive identity (0).
func (s *scalar) Zero() kyber.Scalar {
	feZero(&s.fieldElement)
	return s
}

// Set to the modular sum of scalars a and b.
func (s *scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	feAdd(&s.fieldElement, &a.(*scalar).fieldElement, &b.(*scalar).fieldElement)
	return s
}

// Set to the modular difference a - b.
func (s *scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	feSub(&s.fieldElement, &a.(*scalar).fieldElement, &b.(*scalar).fieldElement)
	return s
}

// Set to the modular negation of scalar a.
func (s *scalar) Neg(a kyber.Scalar) kyber.Scalar {
	var z fieldElement
	feZero(&z)
	feSub(&s.fieldElement, &z, &a.(*scalar).fieldElement)
	return s
}

// Set to the multiplicative identity (1).
func (s *scalar) One() kyber.Scalar {
	feOne(&s.fieldElement)
	return s
}

// Set to the modular product of scalars a and b.
func (s *scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	feMul(&s.fieldElement, &a.(*scalar).fieldElement, &b.(*scalar).fieldElement)
	return s
}

// Set to the modular division of scalar a by scalar b.
func (s *scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	var inv fieldElement
	feInvert(&inv, &b.(*scalar).fieldElement)
	feMul(&s.fieldElement, &a.(*scalar).fieldElement, &inv)
	return s
}

// Set to the modular inverse of scalar a.
func (s *scalar) Inv(a kyber.Scalar) kyber.Scalar {
	feInvert(&s.fieldElement, &s.fieldElement)
	return s
}

// Set to a fresh random or pseudo-random scalar.
func (s *scalar) Pick(rand cipher.Stream) kyber.Scalar {
	var b [32]byte
	rand.XORKeyStream(b[:], b[:])
	return s.SetBytes(b[:])
}

// SetBytes sets the scalar from a byte-slice,
// reducing if necessary to the appropriate modulus.
// The endianess of the byte-slice is determined by the
// implementation.
func (s *scalar) SetBytes(src []byte) kyber.Scalar {
	var sa [32]byte
	copy(sa[:], src)
	feFromBytes(&s.fieldElement, &sa)
	return s
}

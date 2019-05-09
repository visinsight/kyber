package curve25519

import (
	"crypto/cipher"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v3/group/internal/marshalling"

	"go.dedis.ch/kyber/v3"
)

const b = 486662

type point struct {
	X fieldElement
	Y fieldElement
}

func (p point) MarshalBinary() (data []byte, err error) {
	var buf [32]byte
	feToBytes(&buf, &p.X)
	return buf[:], nil
}

func (p *point) UnmarshalBinary(data []byte) error {
	var buf [32]byte
	copy(buf[:], data)
	feFromBytes(&p.X, &buf)
	return nil
}

// String returns the human readable string representation of the object.
func (p point) String() string {
	return fmt.Sprintf("%x", p.X)
}

// Encoded length of this object in bytes.
func (p *point) MarshalSize() int {
	return 32
}

// Encode the contents of this object and write it to an io.Writer.
func (p *point) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(p, w)
}

// Decode the content of this object by reading from an io.Reader.
// If r is an XOF, it uses r to pick a valid object pseudo-randomly,
// which may entail reading more than Len bytes due to retries.
func (p *point) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}

// Equality test for two Points derived from the same Group.
func (p *point) Equal(s2 kyber.Point) bool {
	return p.X == s2.(*point).X
}

// Null sets the receiver to the neutral identity element.
func (p *point) Null() kyber.Point {
	p.X = fieldElement{}
	return p
}

// Base sets the receiver to this group's standard base point.
func (p *point) Base() kyber.Point {
	p.UnmarshalBinary(basePoint[:])
	return p
}

// Pick sets the receiver to a fresh random or pseudo-random Point.
func (p *point) Pick(rand cipher.Stream) kyber.Point {
	var buf := make([]byte, 32)
	rand.XORKeyStream(buf, buf)
	feFromBytes(&p.X)
	return p
}

// Set sets the receiver equal to another Point p.
func (p *point) Set(p2 kyber.Point) kyber.Point {
	p.X = p2.(*point).X
	p.Z = p2.(*point).Z
	return p

}

// Clone clones the underlying point.
func (p *point) Clone() kyber.Point {
	var c point
	c.Set(p)
	return &c
}

// Maximum number of bytes that can be embedded in a single
// group element via Pick().
func (p *point) EmbedLen() int {
	return 28
}

// Embed encodes a limited amount of specified data in the
// Point, using r as a source of cryptographically secure
// random data.  Implementations only embed the first EmbedLen
// bytes of the given data.
func (p *point) Embed(data []byte, r cipher.Stream) kyber.Point {
	return p.Base()
}

// Extract data embedded in a point chosen via Embed().
// Returns an error if doesn't represent valid embedded data.
func (p *point) Data() ([]byte, error) {
	return []byte{}, nil
}

// Add points so that their scalars add homomorphically.
func (p *point) Add(a, b kyber.Point) kyber.Point {
	// x3 = B(x2y1 - x1y2)^2 / x1x2(x2 - x1)^2
	// y3 = (2x1 + x2 + A)(y2 - y1) / (x2 - x1) -
	//		B(y2 -y1)^3 / (x2 - x1)^3 -
	//		y1
	var x3 fieldElement

	return p
}

// Subtract points so that their scalars subtract homomorphically.
func (p *point) Sub(a, b kyber.Point) kyber.Point {
	return p
}

// Set to the negation of point a.
func (p *point) Neg(a kyber.Point) kyber.Point {
	return p
}

// Multiply point p by the scalar s.
// If p2 == nil, multiply with the standard base point Base().
func (p *point) Mul(s kyber.Scalar, p2 kyber.Point) kyber.Point {
	px := basePoint
	if p2 != nil {
		px = p2.(*point).X
	}
	var sbuf [32]byte
	feToBytes(&sbuf, &s.(*scalar).fieldElement)
	ScalarMult(&p.X, &sbuf, &px)
	return p
}

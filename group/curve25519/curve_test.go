package curve25519

import (
	"testing"

	"go.dedis.ch/kyber/v3/util/test"
)

var testSuite = NewBlakeSHA256Curve25519()

// Test each curve implementation of the Ed25519 curve.

func TestCurve25519(t *testing.T) {
	test.GroupTest(t, testSuite)
}

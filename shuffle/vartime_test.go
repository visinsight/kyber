package shuffle

import (
	"testing"

	"go.dedis.ch/kyber/v3/group/p256"
)

func BenchmarkBiffleP256(b *testing.B) {
	biffleTest(p256.NewBlakeSHA256P256(), b.N)
}

func Benchmark2PairShuffleP256(b *testing.B) {
	shuffleTest(p256.NewBlakeSHA256P256(), 2, b.N)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	shuffleTest(p256.NewBlakeSHA256P256(), 10, b.N)
}

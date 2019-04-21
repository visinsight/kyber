package suites

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSuites_Find(t *testing.T) {
	ss := []string{
		"ed25519",
		"BN256_G1",
		"BN256_G2",
		"BN256_GT",
		"P256",
		"Residue512",
	}

	for _, name := range ss {
		s, err := Find(name)
		require.NotNil(t, s, "missing "+name)
		require.NoError(t, err)

		s = MustFind(name)
		require.NotNil(t, s, "missing "+name)
	}
}

func TestSuites_ConstTime(t *testing.T) {
	RequireConstantTime()
	defer func() { requireConstTime = false }()

	s, err := Find("BN256_G1")
	require.Error(t, err)
	require.Nil(t, s)

	s, err = Find("ed25519")
	require.NoError(t, err)
	require.NotNil(t, s)
}

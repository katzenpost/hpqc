package x25519

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestElligator(t *testing.T) {
	seed, err := hex.DecodeString("c1582d56550a87e1635ae1acf1d28d967f855d7ac5ccec475f50e16a93864ce5")
	require.NoError(t, err)
	seedArr := [keySize]byte{}
	copy(seedArr[:], seed)
	pk, sk := GenerateHiddenKeyPair(&seedArr)

	expectedPk, err := hex.DecodeString("755e64bb7cfacffda60daddd26c089c31b98367373b001938e056be139ed6f47")
	require.NoError(t, err)

	expectedSk, err := hex.DecodeString("3c1d09563d0305764b6db5a82190da5b5852d0c65af937010e3b0ac6db7d49b3")
	require.NoError(t, err)

	require.Equal(t, pk, expectedPk)
	require.Equal(t, sk, expectedSk)

	curve := Unelligator(pk)

	expectedCurve, err := hex.DecodeString("7b6e740a2d4f48ca46e2f1056075886fbf58e554c2b9d94d0d0d343d6bb64672")
	require.NoError(t, err)
	require.Equal(t, curve, expectedCurve)
}

package diffiehellman

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPaddedBinaryEncode verifies that paddedBinaryEncode always returns
// a fixed-size output even when the underlying big integer has leading
// zero bytes. See https://github.com/katzenpost/hpqc/issues/39.
func TestPaddedBinaryEncode(t *testing.T) {
	s := Scheme()
	group := s.group()

	// A small value in the group has hundreds of leading zero bytes,
	// so this directly exercises the padding path.
	small := group.NewInt(42)
	encoded := paddedBinaryEncode(small)
	require.Equal(t, groupSize+8, len(encoded))

	// Verify the value survives a round-trip through BinaryDecode.
	key := &PrivateKey{privateKey: small}
	restored := s.NewEmptyPrivateKey()
	require.NoError(t, restored.FromBytes(key.Bytes()))
	require.Equal(t, key.Bytes(), restored.Bytes())
}

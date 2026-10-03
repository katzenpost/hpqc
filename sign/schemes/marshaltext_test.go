// SPDX-License-Identifier: AGPL-3.0-only

package schemes_test

import (
	"encoding"
	"testing"

	"github.com/stretchr/testify/require"

	signpem "github.com/katzenpost/hpqc/sign/pem"
	"github.com/katzenpost/hpqc/sign/schemes"
)

func TestPublicKeyMarshalText(t *testing.T) {
	for _, s := range schemes.All() {
		t.Run(s.Name(), func(t *testing.T) {
			pub, _, err := s.GenerateKey()
			require.NoError(t, err)
			m, ok := pub.(encoding.TextMarshaler)
			require.True(t, ok)
			text, err := m.MarshalText()
			require.NoError(t, err)
			got, err := signpem.FromPublicPEMString(string(text), s)
			require.NoError(t, err)
			require.True(t, got.Equal(pub))
		})
	}
}

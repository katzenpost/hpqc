// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"
)

func TestKEMTextUnmarshal(t *testing.T) {
	todo := All()

	dir, err := ioutil.TempDir("", "example")
	require.NoError(t, err)

	testkem := func(s kem.Scheme) {

		pubkey, privkey, err := s.GenerateKeyPair()
		require.NoError(t, err)

		blob1, err := pubkey.MarshalText()
		require.NoError(t, err)

		testpubkey2, err := s.UnmarshalTextPublicKey(blob1)
		require.NoError(t, err)

		blob2, err := testpubkey2.MarshalText()
		require.NoError(t, err)

		require.Equal(t, blob1, blob2)

		// test private key marshaling/unmarshaling
		privfile := filepath.Join(dir, "privkey.pem")
		err = pem.PrivateKeyToFile(privfile, privkey)
		require.NoError(t, err)

		privkey2, err := pem.FromPrivatePEMFile(privfile, s)
		require.NoError(t, err)

		blob1, err = privkey.MarshalBinary()
		require.NoError(t, err)

		blob2, err = privkey2.MarshalBinary()
		require.NoError(t, err)

		require.Equal(t, blob1, blob2)
		require.True(t, privkey2.Equal(privkey))

		err = os.Remove(privfile)
		require.NoError(t, err)
	}

	for _, scheme := range todo {
		t.Logf("testing KEM Scheme: %s", scheme.Name())
		testkem(scheme)
		t.Log("OK")
	}
}

func TestKEMEncapDecap(t *testing.T) {
	todo := All()

	testkem := func(s kem.Scheme) {
		pubkey1, privkey1, err := s.GenerateKeyPair()
		require.NoError(t, err)

		ct1, ss1, err := s.Encapsulate(pubkey1)
		require.NoError(t, err)

		ss2, err := s.Decapsulate(privkey1, ct1)
		require.NoError(t, err)

		require.Equal(t, ss1, ss2)
	}

	for _, scheme := range todo {
		t.Logf("testing KEM Scheme: %s", scheme.Name())
		testkem(scheme)
		t.Log("OK")
	}
}

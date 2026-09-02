// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package adapter

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/blake2b"
)

// TestBLAKE2bXOFVectors consumes the BLAKE2b XOF (BLAKE2Xb) vectors. This is the primitive the
// adapter's deployed PRF keys with the raw shared secret, so it sits directly beneath
// TestSharedAdapterVectors: if the adapter vectors fail, these say whether the cause is the
// construction or the hash.
//
// The `xof_size` field is load-bearing. The requested output length is folded into BLAKE2Xb's
// parameter block, so it changes the output stream — two vectors here share key, message and
// read length while differing only in xof_size, and must produce different bytes. An
// implementation that ignores the field fails on exactly that pair.
func TestBLAKE2bXOFVectors(t *testing.T) {
	var vectors []struct {
		Name    string `json:"name"`
		KeyHex  string `json:"key_hex"`
		MsgHex  string `json:"msg_hex"`
		XOFSize uint32 `json:"xof_size"`
		Length  int    `json:"length"`
		OutHex  string `json:"out_hex"`
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "blake2b_xof.json"))
	require.NoError(t, err)
	var envelope struct {
		FormatVersion int             `json:"format_version"`
		Primitive     string          `json:"primitive"`
		Vectors       json.RawMessage `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.Equal(t, 1, envelope.FormatVersion)
	require.Equal(t, "blake2b_xof", envelope.Primitive)
	require.NoError(t, json.Unmarshal(envelope.Vectors, &vectors))
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			key := mustHex(t, v.KeyHex)
			msg := mustHex(t, v.MsgHex)
			want := mustHex(t, v.OutHex)
			require.Len(t, want, v.Length, "out_hex length must match the length field")

			x, err := blake2b.NewXOF(v.XOFSize, key)
			require.NoError(t, err)
			_, err = x.Write(msg)
			require.NoError(t, err)

			got := make([]byte, v.Length)
			_, err = io.ReadFull(x, got)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	// Guard the property the file exists to pin: same key, same message, same read length,
	// different xof_size must give different output. If a future edit makes these collide,
	// the file has stopped testing what it claims to.
	var a, b string
	for _, v := range vectors {
		switch v.Name {
		case "adapter_shape_32byte_key_64byte_msg_32":
			a = v.OutHex
		case "same_inputs_size_64_read_32":
			b = v.OutHex
		}
	}
	require.NotEmpty(t, a, "expected vector adapter_shape_32byte_key_64byte_msg_32")
	require.NotEmpty(t, b, "expected vector same_inputs_size_64_read_32")
	require.NotEqual(t, a, b, "xof_size must affect the output stream")
}

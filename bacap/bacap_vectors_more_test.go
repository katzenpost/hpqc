// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Consumers for the layout, tombstone, position and negative vector files.
// The Python port reads the same files in py/tests/bacap/.

func TestBACAPLayoutVectors(t *testing.T) {
	var vectors []struct {
		Name                     string `json:"name"`
		WriteCapHex              string `json:"writecap_hex"`
		ExpectedRootPublicKeyHex string `json:"expected_root_public_key_hex"`
		ExpectedReadCapHex       string `json:"expected_readcap_hex"`
		ExpectedIndexHex         string `json:"expected_index_hex"`
		ExpectedIdx64            uint64 `json:"expected_idx64"`
	}
	loadBACAPVectorFile(t, "layout.json", "bacap_layout", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			wcBytes := mustHexBytes(t, v.WriteCapHex)
			wc, err := NewWriteCapFromBytes(wcBytes)
			require.NoError(t, err)
			again, err := wc.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, wcBytes, again, "WriteCap does not round-trip")

			rc := wc.ReadCap()
			require.Equal(t, mustHexBytes(t, v.ExpectedRootPublicKeyHex), rc.RootPublicKey().Bytes(), "root public key")
			rcBytes, err := rc.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, mustHexBytes(t, v.ExpectedReadCapHex), rcBytes, "derived ReadCap")

			parsed, err := ReadCapFromBytes(rcBytes)
			require.NoError(t, err)
			again, err = parsed.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, rcBytes, again, "ReadCap does not round-trip")

			idx := wc.GetMessageBoxIndex()
			idxBytes, err := idx.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, mustHexBytes(t, v.ExpectedIndexHex), idxBytes, "MessageBoxIndex")
			require.Equal(t, v.ExpectedIdx64, idx.Idx64, "Idx64")
		})
	}
}

func TestBACAPTombstoneVectors(t *testing.T) {
	var vectors []struct {
		Name                 string `json:"name"`
		WriteCapHex          string `json:"writecap_hex"`
		AdvanceBy            uint64 `json:"advance_by"`
		CtxHex               string `json:"ctx_hex"`
		ExpectedBoxIDHex     string `json:"expected_box_id_hex"`
		ExpectedSignatureHex string `json:"expected_signature_hex"`
	}
	loadBACAPVectorFile(t, "tombstone.json", "bacap_tombstone", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			wc, err := NewWriteCapFromBytes(mustHexBytes(t, v.WriteCapHex))
			require.NoError(t, err)
			idx := advanceBy(t, wc.GetMessageBoxIndex(), v.AdvanceBy)
			ctx := mustHexBytes(t, v.CtxHex)

			box, sig, err := idx.SignBox(wc, ctx, []byte{})
			require.NoError(t, err)
			require.Equal(t, mustHexBytes(t, v.ExpectedBoxIDHex), box[:], "box ID")
			require.Equal(t, mustHexBytes(t, v.ExpectedSignatureHex), sig, "signature")

			plaintext, err := idx.DecryptForContext(box, ctx, []byte{}, sig)
			require.NoError(t, err)
			require.Empty(t, plaintext)
		})
	}
}

// reachable reports whether stepping the cap's own index forward reaches
// idx, which is what makes idx part of the cap's stream.
func reachable(t *testing.T, rc *ReadCap, idx *MessageBoxIndex) bool {
	t.Helper()
	start := rc.GetMessageBoxIndex()
	if idx.Idx64 < start.Idx64 {
		return false
	}
	walked, err := start.AdvanceIndexTo(idx.Idx64)
	require.NoError(t, err)
	a, err := walked.MarshalBinary()
	require.NoError(t, err)
	b, err := idx.MarshalBinary()
	require.NoError(t, err)
	return bytes.Equal(a, b)
}

func TestBACAPPositionVectors(t *testing.T) {
	var vectors []struct {
		Name       string `json:"name"`
		ReadCapHex string `json:"readcap_hex"`
		IndexHex   string `json:"index_hex"`
		Reachable  bool   `json:"reachable"`
	}
	loadBACAPVectorFile(t, "position.json", "bacap_position", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			rc, err := ReadCapFromBytes(mustHexBytes(t, v.ReadCapHex))
			require.NoError(t, err)
			idx, err := NewEmptyMessageBoxIndexFromBytes(mustHexBytes(t, v.IndexHex))
			require.NoError(t, err)
			require.Equal(t, v.Reachable, reachable(t, rc, idx))
		})
	}
}

func advanceBy(t *testing.T, idx *MessageBoxIndex, n uint64) *MessageBoxIndex {
	t.Helper()
	if n == 0 {
		return idx
	}
	out, err := idx.AdvanceIndexTo(idx.Idx64 + n)
	require.NoError(t, err)
	return out
}

func TestBACAPNegativeVectors(t *testing.T) {
	var vectors []struct {
		Name          string  `json:"name"`
		Operation     string  `json:"operation"`
		Category      string  `json:"category"`
		BlobHex       string  `json:"blob_hex"`
		IndexHex      string  `json:"index_hex"`
		AdvanceTo     *uint64 `json:"advance_to"`
		WriteCapHex   string  `json:"writecap_hex"`
		AdvanceBy     uint64  `json:"advance_by"`
		CtxHex        string  `json:"ctx_hex"`
		BoxIDHex      string  `json:"box_id_hex"`
		CiphertextHex string  `json:"ciphertext_hex"`
		SignatureHex  string  `json:"signature_hex"`
	}
	loadBACAPVectorFile(t, "negative.json", "bacap_negative", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			var box [BoxIDSize]byte
			if v.BoxIDHex != "" {
				copy(box[:], mustHexBytes(t, v.BoxIDHex))
			}
			ct := mustHexBytes(t, v.CiphertextHex)
			sig := mustHexBytes(t, v.SignatureHex)
			ctx := mustHexBytes(t, v.CtxHex)
			capIndex := func() (*WriteCap, *MessageBoxIndex) {
				wc, err := NewWriteCapFromBytes(mustHexBytes(t, v.WriteCapHex))
				require.NoError(t, err)
				return wc, advanceBy(t, wc.GetMessageBoxIndex(), v.AdvanceBy)
			}

			switch v.Operation {
			case "advance_index_to":
				idx, err := NewEmptyMessageBoxIndexFromBytes(mustHexBytes(t, v.IndexHex))
				require.NoError(t, err)
				require.NotNil(t, v.AdvanceTo)
				_, err = idx.AdvanceIndexTo(*v.AdvanceTo)
				require.Error(t, err)
			case "next_index":
				idx, err := NewEmptyMessageBoxIndexFromBytes(mustHexBytes(t, v.IndexHex))
				require.NoError(t, err)
				_, err = idx.NextIndex()
				require.Error(t, err)
			case "decrypt":
				_, idx := capIndex()
				_, err := idx.DecryptForContext(box, ctx, ct, sig)
				require.Error(t, err)
			case "open":
				wc, idx := capIndex()
				expected, err := idx.BoxIDForContext(wc.ReadCap(), ctx)
				require.NoError(t, err)
				require.NotEqual(t, expected.Bytes(), box[:], "the box must differ from the one the cap and index derive")
				// The stateful reader is Go's one open path that checks the box.
				reader, err := NewStatefulReaderWithIndex(wc.ReadCap(), ctx, idx)
				require.NoError(t, err)
				var sigArr [SignatureSize]byte
				copy(sigArr[:], sig)
				_, err = reader.DecryptNext(ctx, box, ct, sigArr)
				require.Error(t, err)
			case "verify_box":
				ok, err := idx0(t).VerifyBox(box, ct, sig)
				require.False(t, ok && err == nil)
			case "parse_message_box_index":
				_, err := NewEmptyMessageBoxIndexFromBytes(mustHexBytes(t, v.BlobHex))
				require.Error(t, err)
			case "parse_read_cap":
				_, err := ReadCapFromBytes(mustHexBytes(t, v.BlobHex))
				require.Error(t, err)
			case "parse_write_cap":
				_, err := NewWriteCapFromBytes(mustHexBytes(t, v.BlobHex))
				require.Error(t, err)
			default:
				t.Fatalf("unknown operation %q", v.Operation)
			}
		})
	}
}

// idx0 is any index: VerifyBox does not depend on the receiver.
func idx0(t *testing.T) *MessageBoxIndex {
	t.Helper()
	return NewEmptyMessageBoxIndex()
}

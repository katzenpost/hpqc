// SPDX-License-Identifier: AGPL-3.0-only

package mldsa

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
)

type wycheproofVerifyFile struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		PublicKey string `json:"publicKey"`
		Tests     []struct {
			TcID   int    `json:"tcId"`
			Msg    string `json:"msg"`
			Sig    string `json:"sig"`
			Ctx    string `json:"ctx"`
			Result string `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func TestWycheproofVerify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		file   string
		scheme sign.Scheme
	}{
		{"ML-DSA-44", "mldsa_44_verify_test.json", Scheme44()},
		{"ML-DSA-65", "mldsa_65_verify_test.json", Scheme65()},
		{"ML-DSA-87", "mldsa_87_verify_test.json", Scheme87()},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			checkWycheproofVerify(t, tt.scheme, tt.file)
		})
	}
}

func checkWycheproofVerify(t *testing.T, scheme sign.Scheme, filename string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", filename))
	require.NoError(t, err)
	var vectors wycheproofVerifyFile
	require.NoError(t, json.Unmarshal(raw, &vectors))

	decode := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		require.NoError(t, err)
		return decoded
	}
	caseCount := 0
	for groupIndex, group := range vectors.TestGroups {
		publicKey, keyErr := scheme.UnmarshalBinaryPublicKey(decode(group.PublicKey))
		for _, tc := range group.Tests {
			caseCount++
			if tc.Ctx != "" {
				t.Run(fmt.Sprintf("group_%d_tcId_%d", groupIndex, tc.TcID), func(t *testing.T) {
					t.Skip("non-empty ML-DSA context is unsupported by sign.Scheme.Verify")
				})
				continue
			}

			verified := false
			if keyErr == nil {
				verified = scheme.Verify(publicKey, decode(tc.Msg), decode(tc.Sig), nil)
			}
			switch tc.Result {
			case "valid":
				require.NoError(t, keyErr, "group %d tcId %d", groupIndex, tc.TcID)
				require.True(t, verified, "group %d tcId %d", groupIndex, tc.TcID)
			case "invalid":
				require.False(t, verified, "group %d tcId %d", groupIndex, tc.TcID)
			case "acceptable":
			default:
				require.FailNow(t, "unknown Wycheproof result", "group %d tcId %d: %s", groupIndex, tc.TcID, tc.Result)
			}
		}
	}
	require.Equal(t, vectors.NumberOfTests, caseCount)
}

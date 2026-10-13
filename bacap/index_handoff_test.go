// SPDX-FileCopyrightText: © 2026 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

// TestIndexHandoffByIdx64 checks that a reader holding only a ReadCap and the
// writer's bare Idx64 derives the same MessageBoxIndex as the writer by
// advancing the ReadCap's starting index to it.
func TestIndexHandoffByIdx64(t *testing.T) {
	t.Parallel()

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	rcap := owner.ReadCap()

	writerIdx := owner.GetMessageBoxIndex()
	for i := 0; i < 17; i++ {
		writerIdx, err = writerIdx.NextIndex()
		require.NoError(t, err)
	}
	target := writerIdx.Idx64

	readerIdx, err := rcap.GetMessageBoxIndex().AdvanceIndexTo(target)
	require.NoError(t, err)
	require.Equal(t, writerIdx, readerIdx)
}

package bacap

import (
"testing"
"math/rand"
	"time"
	"github.com/stretchr/testify/assert"
//	"github.com/stretchr/testify/require"

)

// Check that advancing mailbox states:
// - increment Idx by 1
// - changes CurBlind
// - changes StateBlind
// - advancing the same independently produces the same new state (hoping to detect accidental mutation)
func TestAdvanceIndex(t *testing.T) {
  t.Parallel()
  assert := assert.New(t)
  test_seed := time.Now().UnixNano()
  t.Log("TestAdvanceIndex test_seed", test_seed)
  rng := rand.New(rand.NewSource(test_seed))

  mb_r := NewMailboxIndex(rng)
  mb_1a := AdvanceIndex(mb_r)
  mb_1b := AdvanceIndex(mb_r)
  assert.Equal(mb_1a, mb_1b)
  assert.Equal(1 + mb_r.Idx64, mb_1a.Idx64)
  assert.NotEqual(mb_r.CurBlind, mb_1b.CurBlind)
  assert.NotEqual(mb_r.StateBlind, mb_1b.StateBlind)

  mb_2a := AdvanceIndex(&mb_1a)
  mb_2b := AdvanceIndex(&mb_1b)
  assert.Equal(mb_2a, mb_2b)
  assert.NotEqual(mb_1a, mb_2a)
  assert.NotEqual(mb_1a, mb_2b)
  assert.Equal(1 + mb_1a.Idx64, mb_2a.Idx64)
  assert.NotEqual(mb_1a.CurBlind[:], mb_2b.CurBlind[:])
  assert.NotEqual(mb_1a.StateBlind[:], mb_2b.StateBlind[:])
  
  assert.Equal(2 + mb_r.Idx64, mb_2a.Idx64)
  mb_1c := AdvanceIndex(mb_r)
  assert.Equal(mb_1c, mb_1a)
  mb_2c := AdvanceIndex(&mb_1c)
  assert.Equal(mb_2c, mb_2a)
  assert.Equal(1 + mb_r.Idx64, mb_1c.Idx64)
  assert.Equal(2 + mb_r.Idx64, mb_2c.Idx64)
}

func TestReadCap(t *testing.T) {
  t.Parallel()
  assert := assert.New(t)
  test_seed := time.Now().UnixNano()
  t.Log("TestReadCap test_seed", test_seed)
  rng := rand.New(rand.NewSource(test_seed))

  owner := NewOwner(rng)
  uread := NewUniversalReadCap(owner)
  assert.Equal(owner.firstMailboxIndex.Idx64, uread.firstIndex)
  _ = assert
  _ = uread
}
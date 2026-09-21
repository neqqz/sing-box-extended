package tls

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRandomPrefixes(t *testing.T) {
	t.Run("empty and blank entries are skipped", func(t *testing.T) {
		list, err := ParseRandomPrefixes(nil)
		require.NoError(t, err)
		require.Empty(t, list)

		list, err = ParseRandomPrefixes([]string{""})
		require.NoError(t, err)
		require.Empty(t, list)
	})

	t.Run("multiple entries with and without mask", func(t *testing.T) {
		list, err := ParseRandomPrefixes([]string{"aabb", "", "ccdd/ff00"})
		require.NoError(t, err)
		require.Len(t, list, 2)
		require.Equal(t, []byte{0xaa, 0xbb}, list[0].Prefix)
		require.Nil(t, list[0].Mask)
		require.Equal(t, []byte{0xff, 0xff}, list[0].FullMask())
		require.Equal(t, []byte{0xcc, 0xdd}, list[1].Prefix)
		require.Equal(t, []byte{0xff, 0x00}, list[1].Mask)
	})

	t.Run("errors", func(t *testing.T) {
		for _, bad := range []string{
			"zz",                                   // not hex
			"aabb/zz",                              // mask not hex
			"aabb/ff",                              // mask length mismatch
			"/ff",                                  // empty prefix
			string(bytes.Repeat([]byte("aa"), 33)), // 33 bytes
		} {
			_, err := ParseRandomPrefixes([]string{"aabb", bad})
			require.Error(t, err, bad)
		}
	})
}

func TestRandomPrefixMatch(t *testing.T) {
	random := make([]byte, 32)
	copy(random, []byte{0xaa, 0xbb, 0xcc, 0xdd})

	list, err := ParseRandomPrefixes([]string{"aabb", "1122", "ccee/ff00"})
	require.NoError(t, err)

	require.True(t, list[0].Match(random))
	require.False(t, list[1].Match(random))
	// mask ff00: only the first byte (0xcc) is compared, the second is ignored
	require.False(t, list[2].Match(random)) // random[0] is 0xaa, not 0xcc

	require.True(t, MatchAnyRandomPrefix(list, random))
	require.False(t, MatchAnyRandomPrefix(list[1:2], random))
	require.False(t, MatchAnyRandomPrefix(nil, random))

	masked := RandomPrefix{Prefix: []byte{0xaa, 0x00}, Mask: []byte{0xff, 0x00}}
	require.True(t, masked.Match(random))

	// random shorter than the prefix never matches
	require.False(t, list[0].Match([]byte{0xaa}))
}

func TestPickRandomPrefix(t *testing.T) {
	list, err := ParseRandomPrefixes([]string{"01", "02", "03"})
	require.NoError(t, err)

	seen := map[byte]bool{}
	for i := 0; i < 500; i++ {
		seen[PickRandomPrefix(list).Prefix[0]] = true
	}
	require.Len(t, seen, 3, "every entry should be picked eventually")

	single := list[:1]
	for i := 0; i < 10; i++ {
		require.Equal(t, []byte{0x01}, PickRandomPrefix(single).Prefix)
	}
}

func TestParseRandomPrefixSecrets(t *testing.T) {
	list, err := ParseRandomPrefixSecrets(nil)
	require.NoError(t, err)
	require.Empty(t, list)

	list, err = ParseRandomPrefixSecrets([]string{"", "0011", "", "ff"})
	require.NoError(t, err)
	require.Equal(t, [][]byte{{0x00, 0x11}, {0xff}}, list)

	_, err = ParseRandomPrefixSecrets([]string{"0011", "xyz"})
	require.Error(t, err)

	require.False(t, HasNonEmpty(nil))
	require.False(t, HasNonEmpty([]string{"", ""}))
	require.True(t, HasNonEmpty([]string{"", "aa"}))
}

func TestMatchRotatingRandomPrefixBound(t *testing.T) {
	secretA := []byte("secret-of-user-a")
	secretB := []byte("secret-of-user-b")
	secretC := []byte("secret-of-user-c")
	bind := []byte("key-share-bytes")
	const (
		length = 8
		window = 60
		now    = int64(1_800_000_030)
	)
	cur := CurrentRandomPrefixWindow(now, window)

	makeRandom := func(secret []byte, w int64, bindValue []byte) []byte {
		random := make([]byte, 32)
		copy(random, DeriveRotatingRandomPrefixBound(secret, length, w, bindValue))
		return random
	}

	servers := [][]byte{secretA, secretB}

	// any configured secret is accepted
	require.True(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretA, cur, bind), bind, now))
	require.True(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretB, cur, bind), bind, now))
	// unknown secret is rejected
	require.False(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretC, cur, bind), bind, now))
	// neighbouring windows are tolerated, farther ones are not
	require.True(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretB, cur-1, bind), bind, now))
	require.True(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretB, cur+1, bind), bind, now))
	require.False(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretB, cur+2, bind), bind, now))
	// bound to the key_share of this handshake
	require.False(t, MatchRotatingRandomPrefixBound(servers, length, window, makeRandom(secretA, cur, bind), []byte("other"), now))
	// degenerate inputs
	require.False(t, MatchRotatingRandomPrefixBound(nil, length, window, makeRandom(secretA, cur, bind), bind, now))
	require.False(t, MatchRotatingRandomPrefixBound(servers, length, window, make([]byte, 4), bind, now))
}

func TestPickRandomPrefixSecret(t *testing.T) {
	list := [][]byte{{1}, {2}, {3}}
	seen := map[byte]bool{}
	for i := 0; i < 500; i++ {
		seen[PickRandomPrefixSecret(list)[0]] = true
	}
	require.Len(t, seen, 3)
	require.Equal(t, []byte{9}, PickRandomPrefixSecret([][]byte{{9}}))
}

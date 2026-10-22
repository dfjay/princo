package secrets

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewUUID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	a, b := NewUUID(), NewUUID()
	require.Regexp(t, re, a)
	require.NotEqual(t, a, b)
}

func TestNewRealityKeyPair(t *testing.T) {
	private, public, err := NewRealityKeyPair()
	require.NoError(t, err)
	got, err := RealityPublicKey(private)
	require.NoError(t, err)
	require.Equal(t, public, got)
	_, err = RealityPublicKey("not a key")
	require.Error(t, err)
}

func TestNewHex(t *testing.T) {
	require.Regexp(t, `^[0-9a-f]{32}$`, NewHex(16))
}

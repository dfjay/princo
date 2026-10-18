package secrets

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSecretOrPlain_UnmarshalPlainString(t *testing.T) {
	var s SecretOrPlain
	require.NoError(t, yaml.Unmarshal([]byte(`"hello"`), &s))
	require.True(t, s.IsPlain())
	require.Equal(t, "hello", s.Plain)
}

func TestSecretOrPlain_UnmarshalSecretTag(t *testing.T) {
	var s SecretOrPlain
	require.NoError(t, yaml.Unmarshal([]byte(`!secret uuids/alice`), &s))
	require.False(t, s.IsPlain())
	require.Equal(t, "uuids/alice", s.SecretPath)
}

func TestSecretOrPlain_ResolveFromStore(t *testing.T) {
	store := &Store{values: map[string]any{
		"uuids": map[string]any{"alice": "alice-uuid"},
	}}

	plain := SecretOrPlain{Plain: "plain-value"}
	got, err := plain.Resolve(store)
	require.NoError(t, err)
	require.Equal(t, "plain-value", got)

	ref := SecretOrPlain{SecretPath: "uuids/alice"}
	got, err = ref.Resolve(store)
	require.NoError(t, err)
	require.Equal(t, "alice-uuid", got)
}

func TestSecretOrPlain_Resolve_MissingPath(t *testing.T) {
	store := &Store{values: map[string]any{}}
	ref := SecretOrPlain{SecretPath: "uuids/missing"}
	_, err := ref.Resolve(store)
	require.ErrorContains(t, err, "uuids/missing")
}

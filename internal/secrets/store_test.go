package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

func TestStore_SaveAndOpen_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "secrets.age")
	idPath := filepath.Join(tmp, "key.txt")
	recipientsPath := filepath.Join(tmp, "recipients")

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(idPath, []byte(identity.String()+"\n"), 0600))
	require.NoError(t, os.WriteFile(recipientsPath, []byte(identity.Recipient().String()+"\n"), 0644))

	// Save plaintext map to an encrypted store.
	plain := map[string]any{
		"uuids": map[string]any{"alice": "alice-uuid", "bob": "bob-uuid"},
	}
	require.NoError(t, Save(storePath, recipientsPath, plain))

	// File should be armored age (text starting with "-----BEGIN AGE ENCRYPTED FILE-----").
	raw, err := os.ReadFile(storePath)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(raw, []byte("-----BEGIN AGE ENCRYPTED FILE-----")))

	// Open should give us back the same map.
	store, err := Open(storePath, idPath)
	require.NoError(t, err)
	uuids, ok := store.values["uuids"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "alice-uuid", uuids["alice"])
	require.Equal(t, "bob-uuid", uuids["bob"])
}

func TestStore_Get_NestedPath(t *testing.T) {
	store := &Store{values: map[string]any{
		"uuids":   map[string]any{"alice": "alice-uuid"},
		"reality": map[string]any{"edge": map[string]any{"private": "rk-priv"}},
	}}

	got, err := store.Get("uuids/alice")
	require.NoError(t, err)
	require.Equal(t, "alice-uuid", got)

	got, err = store.Get("reality/edge/private")
	require.NoError(t, err)
	require.Equal(t, "rk-priv", got)
}

func TestStore_Get_DotAndSlashEquivalent(t *testing.T) {
	store := &Store{values: map[string]any{
		"uuids": map[string]any{"alice": "alice-uuid"},
	}}
	got, err := store.Get("uuids.alice")
	require.NoError(t, err)
	require.Equal(t, "alice-uuid", got)
}

func TestStore_Get_Missing(t *testing.T) {
	store := &Store{values: map[string]any{}}
	_, err := store.Get("uuids/bob")
	require.ErrorContains(t, err, "secret not found")
}

func TestStore_Set_CreatesIntermediate(t *testing.T) {
	store := &Store{values: map[string]any{}}
	require.NoError(t, store.Set("reality/edge/private", "rk-priv"))

	got, err := store.Get("reality/edge/private")
	require.NoError(t, err)
	require.Equal(t, "rk-priv", got)
}

func TestStore_List_FlattensPaths(t *testing.T) {
	store := &Store{values: map[string]any{
		"uuids":   map[string]any{"alice": "x", "bob": "y"},
		"reality": map[string]any{"edge": map[string]any{"private": "z"}},
	}}
	got := store.List()
	require.ElementsMatch(t, []string{
		"uuids/alice",
		"uuids/bob",
		"reality/edge/private",
	}, got)
}

func TestStore_Delete(t *testing.T) {
	store := &Store{values: map[string]any{
		"uuids": map[string]any{"alice": "x", "bob": "y"},
	}}
	require.NoError(t, store.Delete("uuids/alice"))
	_, err := store.Get("uuids/alice")
	require.ErrorContains(t, err, "not found")
	got, err := store.Get("uuids/bob")
	require.NoError(t, err)
	require.Equal(t, "y", got)
}

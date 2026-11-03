package secrets

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	write("users/alice", "uuid-a")
	write("nodes/fr/reality", "rk\n")

	d := Dir(dir)
	for path, want := range map[string]string{
		"users/alice":      "uuid-a",
		"nodes/fr/reality": "rk",
	} {
		got, err := d.Get(path)
		require.NoError(t, err, path)
		require.Equal(t, want, got, path)
	}

	_, err := d.Get("users/bob")
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = d.Get("../outside")
	require.Error(t, err)
	require.NotErrorIs(t, err, fs.ErrNotExist, "escaping the dir is not a missing secret")
}

func TestPlaceholders(t *testing.T) {
	paths := []string{"users/alice", "shared/hysteria2_obfs", "nodes/fr/warp/ipv4"}
	var data []byte
	for _, p := range append(paths, paths[0]) {
		data = append(data, `{"x":"`+Placeholder(p)+`"}`...)
	}
	require.Equal(t, []string{"nodes/fr/warp/ipv4", "shared/hysteria2_obfs", "users/alice"}, Placeholders(data))

	g := OrPlaceholder{NewStore(map[string]any{"users": map[string]any{"alice": "a"}})}
	v, err := g.Get("users/alice")
	require.NoError(t, err)
	require.Equal(t, "a", v)
	_, err = g.Get("users/bob")
	require.ErrorContains(t, err, "not found", "a Store miss is not fs.ErrNotExist")

	g = OrPlaceholder{Dir(t.TempDir())}
	v, err = g.Get("users/bob")
	require.NoError(t, err)
	require.Equal(t, Placeholder("users/bob"), v)
}

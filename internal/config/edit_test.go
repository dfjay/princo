package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const editFixture = `princo: v1

nodes:
  fr:
    address: fr.example.com
    reality:
      short_id: 1a3287df
      public_key: <public key> # sing-box generate reality-keypair
      private_key: !secret keys/fr
  us: { address: us.example.com, reality: { public_key: "old" } }

users:
  alice: { nodes: [fr, us] }
  # family
  bob: {}
  carol:
    nodes: [us]

# Profile the apps import.
client:
  final: direct
`

func TestSetValue(t *testing.T) {
	out, ok, err := SetValue([]byte(editFixture), []string{"nodes", "fr", "reality", "public_key"}, "pub-FR_1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Contains(t, string(out), "      public_key: pub-FR_1 # sing-box generate reality-keypair\n")

	out, ok, err = SetValue(out, []string{"nodes", "us", "reality", "public_key"}, "-starts-with-dash")
	require.NoError(t, err)
	require.True(t, ok)
	require.Contains(t, string(out), `reality: { public_key: "-starts-with-dash" } }`)

	_, ok, err = SetValue(out, []string{"nodes", "us", "reality", "short_id"}, "x")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestAddEntry(t *testing.T) {
	out, err := AddEntry([]byte(editFixture), "users", "dave", "{ nodes: [fr] }")
	require.NoError(t, err)
	require.Contains(t, string(out), "    nodes: [us]\n  dave: { nodes: [fr] }\n\n# Profile the apps import.\n")

	_, err = AddEntry(out, "users", "bob", "{}")
	require.ErrorContains(t, err, "users.bob already exists")

	out, err = AddEntry([]byte("princo: v1\n"), "users", "alice", "{}")
	require.NoError(t, err)
	require.Equal(t, "princo: v1\n\nusers:\n  alice: {}\n", string(out))

	out, err = AddEntry([]byte("princo: v1\nusers:\nclient: {}\n"), "users", "alice", "{}")
	require.NoError(t, err)
	require.Equal(t, "princo: v1\nusers:\n  alice: {}\nclient: {}\n", string(out))

	_, err = AddEntry([]byte("princo: v1\nusers: { bob: {} }\n"), "users", "alice", "{}")
	require.ErrorContains(t, err, "add alice by hand")
}

func TestRemoveEntry(t *testing.T) {
	out, err := RemoveEntry([]byte(editFixture), "users", "alice")
	require.NoError(t, err)
	require.Contains(t, string(out), "users:\n  # family\n  bob: {}\n")

	out, err = RemoveEntry([]byte(editFixture), "users", "carol")
	require.NoError(t, err)
	require.Contains(t, string(out), "  bob: {}\n\n# Profile the apps import.\n")

	out, err = RemoveEntry([]byte("princo: v1\nusers:\n  alice: {}\n"), "users", "alice")
	require.NoError(t, err)
	require.Equal(t, "princo: v1\nusers:\n", string(out))

	_, err = RemoveEntry([]byte(editFixture), "users", "zed")
	require.ErrorContains(t, err, "users.zed doesn't exist")
}

func TestEdit_EdgeCases(t *testing.T) {
	out, ok, err := SetValue([]byte("princo: v1\nnodes:\n  fr:\n    reality:\n      public_key: # later\n"),
		[]string{"nodes", "fr", "reality", "public_key"}, "pub")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "princo: v1\nnodes:\n  fr:\n    reality:\n      public_key: pub # later\n", string(out))

	out, err = AddEntry([]byte("princo: v1\nusers:\n  123: {}\n"), "users", "456", "{}")
	require.NoError(t, err)
	require.Equal(t, "princo: v1\nusers:\n  123: {}\n  \"456\": {}\n", string(out))
	out, err = RemoveEntry(out, "users", "123")
	require.NoError(t, err)
	require.Equal(t, "princo: v1\nusers:\n  \"456\": {}\n", string(out))

	_, err = RemoveEntry([]byte("princo: v1\nusers:\n  alice: {}\n---\nother: 1\n"), "users", "alice")
	require.ErrorContains(t, err, "more than one YAML document")
}

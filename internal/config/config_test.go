package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse_KeepsOrderAndSecrets(t *testing.T) {
	cfg, err := Parse([]byte(`
princo: v1
nodes:
  zz: { address: z.example.com, reality: { private_key: !secret keys/zz } }
  aa: { address: a.example.com }
client:
  groups:
    second: { nodes: b }
    first: { nodes: a }
`))
	require.NoError(t, err)
	require.Equal(t, []string{"zz", "aa"}, cfg.Nodes.Keys())
	require.Equal(t, []string{"second", "first"}, cfg.Client.Groups.Keys())

	zz, _ := cfg.Nodes.Get("zz")
	require.Equal(t, "keys/zz", zz.Reality.PrivateKey.SecretPath)
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	for name, src := range map[string]string{
		"top level":     "princo: v1\nsomething: 1\n",
		"inside a node": "princo: v1\nnodes:\n  a: { adress: x }\n",
		"inside a rule": "princo: v1\ndefaults:\n  rules:\n    - { matches: [port:25] }\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(src))
			require.ErrorContains(t, err, "not found in type")
		})
	}
}

func TestParse_RejectsDuplicateKeys(t *testing.T) {
	_, err := Parse([]byte("princo: v1\nnodes:\n  a: {}\n  a: {}\n"))
	require.ErrorContains(t, err, `duplicate key "a"`)
}

func TestParse_Version(t *testing.T) {
	_, err := Parse([]byte("nodes: {}\n"))
	require.ErrorContains(t, err, "princo: required")
	_, err = Parse([]byte("princo: v9\n"))
	require.ErrorContains(t, err, "unsupported schema version")
}

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/secrets"
)

func TestMerge(t *testing.T) {
	cfg, err := Merge([]File{
		{Path: "/pub/princo.yaml", Data: []byte(`
princo: v1
defaults:
  engine: sing-box
  rules:
    - { action: sniff }
    - { match: [port:25], action: reject }
nodes:
  fr: { ssh: gandi, hysteria2: { obfs: salamander } }
  us: { ssh: linode }
users:
  alice: {}
`)},
		{Path: "/priv/princo.yaml", Data: []byte(`
princo: v1
defaults:
  acme_email: admin@example.com
  rules:
    - { action: sniff }
nodes:
  us: { address: us.example.com }
  fr:
    address: fr.example.com
    hysteria2: { masquerade: https://example.com }
  ru: { address: ru.example.com }
users:
  bob: { nodes: [fr] }
`)},
	})
	require.NoError(t, err)

	require.Equal(t, "sing-box", cfg.Defaults.Engine)
	require.Equal(t, "admin@example.com", cfg.Defaults.ACMEEmail)
	require.Equal(t, []Rule{{Action: "sniff"}}, cfg.Defaults.Rules, "lists are replaced, not appended")

	require.Equal(t, []string{"fr", "us", "ru"}, cfg.Nodes.Keys())
	require.Equal(t, []string{"alice", "bob"}, cfg.Users.Keys())

	fr, _ := cfg.Nodes.Get("fr")
	require.Equal(t, "gandi", fr.SSH)
	require.Equal(t, "fr.example.com", fr.Address)
	require.Equal(t, &Hysteria2{Obfs: "salamander", Masquerade: "https://example.com"}, fr.Hysteria2)
}

func TestMerge_OneFileIsParse(t *testing.T) {
	data := []byte("princo: v1\nnodes:\n  a: { address: a.example.com }\n")
	merged, err := Merge([]File{{Path: "princo.yaml", Data: data}})
	require.NoError(t, err)
	parsed, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, parsed, merged)
}

func TestMerge_EachFileParses(t *testing.T) {
	ok := File{Path: "a.yaml", Data: []byte("princo: v1\n")}
	_, err := Merge([]File{ok, {Path: "b.yaml", Data: []byte("nodes: {}\n")}})
	require.ErrorContains(t, err, "b.yaml: princo: required")
	_, err = Merge([]File{ok, {Path: "b.yaml", Data: []byte("princo: v1\nnodes:\n  a: { adress: x }\n")}})
	require.ErrorContains(t, err, "b.yaml: ")
	require.ErrorContains(t, err, "not found in type")
	_, err = Merge(nil)
	require.Error(t, err)
}

func TestMerge_SecretFiles(t *testing.T) {
	cfg, err := Merge([]File{
		{Path: "/pub/princo.yaml", Data: []byte(`
princo: v1
secrets:
  users/*: sops:pub.yaml#uuid_*
  nodes/*: sops:pub.yaml
  chains/*: sops:pub.yaml
`)},
		{Path: "/priv/princo.yaml", Data: []byte(`
princo: v1
secrets:
  nodes/*: sops:priv.yaml
  shared/*: sops:priv.yaml
  chains/*: ~
`)},
	})
	require.NoError(t, err)
	require.Equal(t, []secrets.Mapping{
		{Pattern: "users/*", Target: "sops:pub.yaml#uuid_*", File: 0},
		{Pattern: "nodes/*", Target: "sops:priv.yaml", File: 1},
		{Pattern: "chains/*", Target: "sops:pub.yaml", File: 0}, // a null keeps the earlier mapping, and its file
		{Pattern: "shared/*", Target: "sops:priv.yaml", File: 1},
	}, cfg.SecretMappings())
}

func TestMerge_NullKeepsEarlierValue(t *testing.T) {
	cfg, err := Merge([]File{
		{Path: "a.yaml", Data: []byte("princo: v1\nusers:\n  alice: {}\ndefaults:\n  egress: warp\n")},
		{Path: "b.yaml", Data: []byte("princo: v1\nusers:\ndefaults:\n  egress: ~\n")},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, cfg.Users.Keys())
	require.Equal(t, "warp", cfg.Defaults.Egress)
}

func TestMerge_ResolvesAliasesPerFile(t *testing.T) {
	cfg, err := Merge([]File{
		{Path: "a.yaml", Data: []byte(`princo: v1
nodes:
  fr: { address: &host fr.example.com, ssh: *host }
`)},
		{Path: "b.yaml", Data: []byte("princo: v1\nnodes:\n  fr: { address: fr.example.org }\n")},
	})
	require.NoError(t, err)
	fr, _ := cfg.Nodes.Get("fr")
	require.Equal(t, "fr.example.org", fr.Address)
	require.Equal(t, "fr.example.com", fr.SSH, "the alias keeps the value it had in its own file")
}

func TestMerge_FlattensMergeKeysPerFile(t *testing.T) {
	cfg, err := Merge([]File{
		{Path: "a.yaml", Data: []byte(`princo: v1
defaults: { acme_email: old@example.com, egress: warp }
nodes:
  fr: { <<: { engine: xray, egress: direct }, address: fr.example.com }
  us: { <<: [{ address: us.example.com, engine: xray }, { engine: sing-box }], egress: warp }
`)},
		{Path: "b.yaml", Data: []byte(`princo: v1
defaults: { <<: { acme_email: new@example.com } }
nodes:
  fr: { engine: sing-box }
`)},
	})
	require.NoError(t, err)
	require.Equal(t, "new@example.com", cfg.Defaults.ACMEEmail, "a merge key in a later file still overrides")
	require.Equal(t, "warp", cfg.Defaults.Egress)
	fr, _ := cfg.Nodes.Get("fr")
	require.Equal(t, "sing-box", fr.Engine)
	require.Equal(t, "direct", fr.Egress)
	require.Equal(t, "fr.example.com", fr.Address)
	us, _ := cfg.Nodes.Get("us")
	require.Equal(t, "us.example.com", us.Address)
	require.Equal(t, "xray", us.Engine, "earlier merged mappings win over later ones")
	require.Equal(t, "warp", us.Egress, "a mapping's own key wins over merged ones")
}

func TestMerge_NullSecretWithoutEarlierMapping(t *testing.T) {
	cfg, err := Merge([]File{
		{Path: "/a/princo.yaml", Data: []byte("princo: v1\n")},
		{Path: "/b/princo.yaml", Data: []byte("princo: v1\nsecrets:\n  users/*: ~\n")},
		{Path: "/c/princo.yaml", Data: []byte("princo: v1\nsecrets:\n  nodes/*: sops:c.yaml\n  chains/*: ~\n")},
	})
	require.NoError(t, err)
	require.Equal(t, []secrets.Mapping{
		{Pattern: "nodes/*", Target: "sops:c.yaml", File: 2},
	}, cfg.SecretMappings())
}

package fleet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/secrets"
)

func build(t *testing.T, src string, values map[string]any) (*Fleet, error) {
	t.Helper()
	cfg, err := config.Parse([]byte("princo: v1\n" + src))
	require.NoError(t, err)
	return Build(cfg, secrets.NewStore(values))
}

// Secrets at their conventional paths for nodes a and b and user u.
func conventionalSecrets() map[string]any {
	return map[string]any{
		"users":  map[string]any{"u": "uuid-u"},
		"shared": map[string]any{"hysteria2_obfs": "obfs"},
		"nodes": map[string]any{
			"a": map[string]any{
				"reality": "key-a",
				"warp":    map[string]any{"private_key": "wk", "ipv4": "v4", "ipv6": "v6"},
				"chain":   "chain-a",
			},
			"b": map[string]any{"reality": "key-b"},
		},
	}
}

func TestBuild_DefaultsAndConventions(t *testing.T) {
	f, err := build(t, `
defaults:
  reality: { server_name: www.example.com }
  egress: warp
  rules:
    - { match: [port:25], action: reject }
nodes:
  a:
    address: a.example.com
    reality: { short_id: "01", public_key: pub-a }
    hysteria2: {}
  b:
    address: b.example.com
    reality: { server_name: www.other.com, short_id: "02", public_key: pub-b }
    egress: direct
    rules: []
users:
  u: {}
`, conventionalSecrets())
	require.NoError(t, err)

	a, _ := f.Node("a")
	require.Equal(t, "www.example.com", a.Reality.ServerName)
	require.Equal(t, "key-a", a.Reality.PrivateKey)
	require.Equal(t, "https://www.example.com", a.Hysteria2.Masquerade, "masquerade defaults to the Reality site")
	require.Empty(t, a.Hysteria2.Obfs)
	require.Empty(t, a.Hysteria2.ObfsPassword)
	require.Equal(t, EgressWarp, a.Egress.Kind)
	require.Equal(t, &Warp{PrivateKey: "wk", IPv4: "v4", IPv6: "v6"}, a.Warp)
	require.Len(t, a.Rules, 1)

	b, _ := f.Node("b")
	require.Equal(t, "www.other.com", b.Reality.ServerName)
	require.Equal(t, EgressDirect, b.Egress.Kind)
	require.Empty(t, b.Rules, "rules: [] replaces the defaults")

	u, _ := f.User("u")
	require.Equal(t, "uuid-u", u.UUID)
	require.Equal(t, []*Node{a, b}, u.Nodes, "no nodes list means all, by name")
	require.True(t, a.IPv6)
}

func TestBuild_Chain(t *testing.T) {
	f, err := build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p }, egress: b }
  b: { address: b.example.com, reality: { server_name: s, short_id: "2", public_key: p } }
users:
  u: {}
`, conventionalSecrets())
	require.NoError(t, err)
	a, _ := f.Node("a")
	b, _ := f.Node("b")
	require.Equal(t, Egress{Kind: EgressNode, Node: b}, a.Egress)
	require.Equal(t, "chain-a", a.ChainUUID)
	require.Equal(t, []*Node{a}, f.ChainsInto(b))
}

func TestBuild_ReportsEveryProblem(t *testing.T) {
	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    egress: b
  b:
    address: b.example.com
    reality: { server_name: s, short_id: "2", public_key: p }
    egress: a
    rules:
      - { match: [geosite], action: reject }
      - { match: [port:25], action: drop }
  c:
    naive: {}
users:
  u: { nodes: [a, nope] }
client:
  groups:
    g: { nodes: x, fallback: missing }
  rules:
    - { match: [geoip:ru], via: other }
  final: nowhere
subscription: { node: zz }
`, conventionalSecrets())
	for _, want := range []string{
		"chain loops back",
		`nodes.b.rules[0]: match "geosite": want kind:value`,
		`nodes.b.rules[1].action: want one of direct, reject, sniff, got "drop"`,
		"nodes.c.naive: domain is required",
		"nodes.b.egress: resolve !secret nodes/b/chain",
		`users.u.nodes: unknown node "nope"`,
		`client.groups.g.fallback: want direct or another group, got "missing"`,
		`client.rules[0].via: unknown group "other"`,
		`client.final: want direct or a group, got "nowhere"`,
		`subscription.node: unknown node "zz"`,
	} {
		require.ErrorContains(t, err, want)
	}
}

func TestBuild_Names(t *testing.T) {
	values := conventionalSecrets()
	values["users"].(map[string]any)["Bad.User"] = "uuid"
	_, err := build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "01", public_key: p } }
  "../b": { address: b.example.com, naive: { domain: b.example.com } }
users:
  u: {}
  Bad.User: {}
client:
  groups:
    "my group": { nodes: all }
`, values)
	require.ErrorContains(t, err, `nodes.../b: name "../b"`)
	require.ErrorContains(t, err, `users.Bad.User: name "Bad.User"`)
	require.ErrorContains(t, err, `client.groups.my group: name "my group"`)
	require.NotContains(t, err.Error(), `name "a"`)
	require.NotContains(t, err.Error(), `name "u"`)
}

func TestParseMatcher(t *testing.T) {
	for _, ok := range []string{"geosite:category-ru", "geoip:ru", "ip:private", "ip:10.0.0.0/8", "port:443", "network:icmp", "domain_suffix:example.com"} {
		_, err := ParseMatcher(ok)
		require.NoError(t, err, ok)
	}
	for _, bad := range []string{"geosite", "ip:10.0.0.1", "port:0", "network:sctp", "color:red"} {
		_, err := ParseMatcher(bad)
		require.Error(t, err, bad)
	}
}

func TestParseDNSAddress(t *testing.T) {
	for in, want := range map[string]DNSServer{
		"9.9.9.9":                           {Type: "udp", Server: "9.9.9.9"},
		"tls://1.1.1.1:853":                 {Type: "tls", Server: "1.1.1.1", Port: 853},
		"https://dns.quad9.net":             {Type: "https", Server: "dns.quad9.net"},
		"https://dns.example.com/resolve":   {Type: "https", Server: "dns.example.com", Path: "/resolve"},
		"https://dns.example.com/dns-query": {Type: "https", Server: "dns.example.com"},
	} {
		got, err := parseDNSAddress(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	_, err := parseDNSAddress("ftp://x")
	require.Error(t, err)
}

func TestBuild_XHTTP(t *testing.T) {
	f, err := build(t, `
defaults:
  xhttp: { path: /shared }
nodes:
  a:
    address: a.example.com
    engine: xray
    reality: { server_name: s, short_id: "1", public_key: p }
    xhttp: {}
users:
  u: {}
`, conventionalSecrets())
	require.NoError(t, err)
	a, _ := f.Node("a")
	require.Equal(t, &XHTTP{Path: "/shared", Mode: "auto"}, a.XHTTP)
	require.Equal(t, []string{"reality", "xhttp"}, a.Protocols())
}

func TestBuild_Hysteria2Obfs(t *testing.T) {
	f, err := build(t, `
defaults:
  hysteria2: { obfs: salamander }
nodes:
  a:
    address: a.example.com
    hysteria2: {}
users:
  u: {}
`, conventionalSecrets())
	require.NoError(t, err)
	a, _ := f.Node("a")
	require.Equal(t, &Hysteria2{Obfs: "salamander", ObfsPassword: "obfs"}, a.Hysteria2)

	f, err = build(t, `
defaults:
  hysteria2: { obfs: salamander, masquerade: https://example.com, obfs_password: !secret shared/hysteria2_obfs }
nodes:
  a: { address: a.example.com, hysteria2: {} }
  b: { address: b.example.com, hysteria2: { obfs: none } }
users:
  u: {}
`, conventionalSecrets())
	require.NoError(t, err)
	a, _ = f.Node("a")
	require.Equal(t, &Hysteria2{Obfs: "salamander", ObfsPassword: "obfs"}, a.Hysteria2)
	b, _ := f.Node("b")
	require.Equal(t, &Hysteria2{Masquerade: "https://example.com"}, b.Hysteria2)

	_, err = build(t, `
nodes:
  a: { address: a.example.com, hysteria2: { obfs: salamander, masquerade: https://example.com } }
  b: { address: b.example.com, hysteria2: { obfs: brutal } }
  c: { address: c.example.com, hysteria2: { masquerade: https://example.com, obfs_password: x } }
  d: { address: d.example.com, hysteria2: {} }
  e: { address: 203.0.113.9, hysteria2: { masquerade: https://example.com } }
`, conventionalSecrets())
	for _, want := range []string{
		"nodes.a.hysteria2.masquerade: has no effect with obfs",
		`nodes.b.hysteria2.obfs: want none, salamander or gecko, got "brutal"`,
		"nodes.c.hysteria2.obfs_password: needs obfs",
		"nodes.d.hysteria2: masquerade is required",
		"nodes.e.hysteria2: needs address to be a domain",
	} {
		require.ErrorContains(t, err, want)
	}
}

func TestBuild_ProtocolNeedsSniff(t *testing.T) {
	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    rules:
      - { match: [protocol:bittorrent], action: reject }
      - { action: sniff }
      - { match: [protocol:quic], action: reject }
      - { match: [protocol:ssh], action: reject }
users:
  u: {}
`, conventionalSecrets())
	require.ErrorContains(t, err, "nodes.a.rules[0]: protocol: needs a sniff rule before it")
	require.NotContains(t, err.Error(), "rules[2]")
	require.ErrorContains(t, err, "protocol must be one of tls, http, quic, bittorrent")
}

func TestBuild_EngineLimits(t *testing.T) {
	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    xhttp: { path: /p }
  b:
    address: b.example.com
    engine: xray
    hysteria2: { masquerade: https://example.com }
    xhttp: { path: "/bad path", mode: fast }
    dns:
      servers: { dot: { address: tls://1.1.1.1 } }
      final: dot
      rules:
        - { match: [domain:example.org] }
    rules:
      - { match: [network:icmp], action: reject }
  c:
    engine: v2ray
    naive: { domain: c.example.com }
users:
  u: {}
`, conventionalSecrets())
	for _, want := range []string{
		"nodes.a.xhttp: engine sing-box doesn't serve it",
		"nodes.b.hysteria2: engine xray doesn't serve it",
		`nodes.b.xhttp.path: want a path such as /a1b2c3`,
		`nodes.b.xhttp.mode: want one of auto, packet-up, stream-up, stream-one, got "fast"`,
		"nodes.b.xhttp: needs reality",
		"nodes.b.dns.servers.dot: xray has no DNS over TLS",
		"nodes.b.rules[0]: xray doesn't route ICMP",
		"nodes.b.dns.rules[0].server: required",
		`nodes.c: engine "v2ray" is not supported (have: sing-box, xray)`,
	} {
		require.ErrorContains(t, err, want)
	}
}

func TestBuild_ClientProtocolWithoutGroups(t *testing.T) {
	_, err := build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: {}
client:
  rules:
    - { match: [protocol:bittorrent], action: reject }
  final: direct
`, conventionalSecrets())
	require.NoError(t, err)
}

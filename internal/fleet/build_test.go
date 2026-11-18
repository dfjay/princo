package fleet

import (
	"strings"
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
	require.Equal(t, &Warp{PrivateKey: "wk", IPv4: "v4", IPv6: "v6", Host: "engage.cloudflareclient.com", Port: 2408}, a.Warp)
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
	for _, bad := range []string{"geosite", "geosite:foo/bar", "ip:10.0.0.1", "port:0", "network:sctp", "color:red"} {
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

func TestBuild_Transports(t *testing.T) {
	f, err := build(t, `
defaults:
  reality:
    server_name: s
    transports:
      grpc: { service_name: shared }
      xhttp: { path: /shared }
nodes:
  a:
    address: a.example.com
    engine: xray
    reality: { short_id: "1", public_key: p, transports: { tcp: {}, xhttp: {} } }
  b:
    address: b.example.com
    reality: { short_id: "2", public_key: p, transports: { grpc: {} } }
    egress: a
  c:
    address: c.example.com
    engine: xray
    reality: { short_id: "3", public_key: p, transports: { xhttp: { path: /own, mode: stream-one } } }
    egress: b
  d:
    address: d.example.com
    reality: { short_id: "4", public_key: p }
users:
  u: {}
`, map[string]any{
		"users": map[string]any{"u": "uuid-u"},
		"nodes": map[string]any{
			"a": map[string]any{"reality": "k"},
			"b": map[string]any{"reality": "k", "chain": "chain-b"},
			"c": map[string]any{"reality": "k", "chain": "chain-c"},
			"d": map[string]any{"reality": "k"},
		},
	})
	require.NoError(t, err)
	a, _ := f.Node("a")
	b, _ := f.Node("b")
	c, _ := f.Node("c")
	d, _ := f.Node("d")
	require.Equal(t, []Transport{{Kind: TransportTCP}, {Kind: TransportXHTTP, Path: "/shared", Mode: "auto"}}, a.Reality.Transports,
		"defaults supply values; the node's blocks enable")
	require.Equal(t, []Transport{{Kind: TransportGRPC, ServiceName: "shared"}}, b.Reality.Transports)
	require.Equal(t, []Transport{{Kind: TransportXHTTP, Path: "/own", Mode: "stream-one"}}, c.Reality.Transports)
	require.Equal(t, []Transport{{Kind: TransportTCP}}, d.Reality.Transports, "tcp without the block")
	require.Equal(t, []string{"reality"}, a.Protocols())

	require.Equal(t, a.Reality.Transports, a.Dials("xray"))
	require.Equal(t, a.Reality.Transports[:1], a.Dials("sing-box"), "sing-box has no XHTTP")
	require.Empty(t, c.Dials(ClientEngine))
	require.Empty(t, (&Node{}).Dials("xray"))
	grpc, ok := b.Dial("xray")
	require.True(t, ok)
	require.Equal(t, "reality-grpc", grpc.Protocol())
	require.False(t, grpc.Vision())
	require.Equal(t, "reality", a.Reality.Transports[0].Protocol())

	require.Equal(t, []Account{{Name: "u", UUID: "uuid-u"}, {Name: "chain:b", UUID: "chain-b"}}, f.Accounts(a, a.Reality.Transports[0]),
		"the hop takes the first transport it speaks")
	require.Equal(t, []Account{{Name: "u", UUID: "uuid-u"}}, f.Accounts(a, a.Reality.Transports[1]))
	require.Equal(t, []Account{{Name: "u", UUID: "uuid-u"}, {Name: "chain:c", UUID: "chain-c"}}, f.Accounts(b, grpc))
}

func TestBuild_TransportLimits(t *testing.T) {
	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p, transports: { xhttp: { path: /p } } }
  b:
    address: b.example.com
    reality: { server_name: s, short_id: "2", public_key: p, transports: { tcp: {}, grpc: { service_name: g } } }
  c:
    address: c.example.com
    engine: xray
    reality: { server_name: s, short_id: "3", public_key: p, transports: { tcp: {}, grpc: { service_name: g } } }
  d:
    address: d.example.com
    engine: xray
    reality: { server_name: s, short_id: "4", public_key: p, transports: { grpc: {}, xhttp: { path: "/bad path", mode: fast } } }
  e:
    address: e.example.com
    reality: { server_name: s, short_id: "5", public_key: p, transports: {} }
  h:
    address: h.example.com
    reality: { server_name: s, short_id: "8", public_key: p }
    egress: e
  f:
    address: f.example.com
    engine: xray
    tags: [only-xhttp]
    reality: { server_name: s, short_id: "6", public_key: p, transports: { xhttp: { path: /p } } }
  g:
    address: g.example.com
    reality: { server_name: s, short_id: "7", public_key: p }
    egress: f
users:
  u: {}
client:
  groups:
    proxy: { relay: only-xhttp }
monitor:
  notify:
    ops: { type: telegram, via: only-xhttp }
`, map[string]any{})
	for _, want := range []string{
		"nodes.a.reality.transports.xhttp: engine sing-box doesn't serve it",
		"nodes.b.reality.transports: engine sing-box serves one transport at a time",
		"nodes.c.reality.transports: engine xray serves one transport at a time, or tcp with xhttp",
		`nodes.d.reality.transports.grpc.service_name: want a name such as a1b2c3 (letters, digits, ., _, ~, -), got ""`,
		`nodes.d.reality.transports.xhttp.path: want a path such as /a1b2c3`,
		`nodes.d.reality.transports.xhttp.mode: want one of auto, packet-up, stream-up, stream-one, got "fast"`,
		"nodes.d.reality.transports: engine xray serves one transport at a time, or tcp with xhttp",
		"nodes.e.reality.transports: enable at least one transport (tcp, grpc, xhttp)",
		"nodes.g.egress: engine sing-box can't connect to chain upstream f, which serves reality over xhttp alone",
		"client.groups.proxy.relay: no node with reality over a transport the profiles speak matches only-xhttp",
		"monitor.notify.ops.via: engine sing-box of node g speaks no reality transport of the nodes it selects",
	} {
		require.ErrorContains(t, err, want)
	}
	require.NotContains(t, err.Error(), "nodes.f.reality.transports", "xray serves XHTTP alone too")
	require.NotContains(t, err.Error(), "upstream e", "a node without transports is reported once")
}

// A node of XHTTP alone is in share links only. A group left with nothing
// else would send the user's traffic directly, which must be asked for.
func TestBuild_UnusableGroups(t *testing.T) {
	cfg := func(nodes, group string) string {
		return `
nodes:
  a:
    address: a.example.com
    engine: xray
    tags: [x]
    reality: { server_name: s, short_id: "1", public_key: p, transports: { xhttp: { path: /p } } }
  b:
    address: b.example.com
    reality: { server_name: s, short_id: "2", public_key: p }
users:
  u: { nodes: ` + nodes + ` }
client:
  groups:
    proxy: ` + group + `
    other: { nodes: none }
  final: proxy
`
	}
	_, err := build(t, cfg("[a]", "{}"), conventionalSecrets())
	require.ErrorContains(t, err, "users.u: group proxy has only nodes the profile can't use (a), which serve no protocol sing-box speaks, and would go direct")
	require.NotContains(t, err.Error(), "group other", "no nodes at all is the fallback's case, as before")

	// A fallback has to lead somewhere: other has no nodes of u's either.
	for _, group := range []string{"{ fallback: other }", "{ fallback: loop }\n    loop: { nodes: none, fallback: proxy }"} {
		_, err := build(t, cfg("[a]", group), conventionalSecrets())
		require.ErrorContains(t, err, "users.u: group proxy has only nodes the profile can't use (a)", group)
	}

	for name, ok := range map[string]string{
		"another node":      cfg("[a, b]", "{}"),
		"to a usable group": cfg("[a, b]", "{ nodes: x, fallback: rest }\n    rest: { nodes: \"!x\" }"),
		"to direct, later":  cfg("[a]", "{ fallback: mid }\n    mid: { nodes: none, fallback: direct }"),
		"asked for":         cfg("[a]", "{ fallback: direct }"),
		"not in the group":  cfg("[a]", "{ nodes: \"!x\" }"),
		"hysteria2 instead": strings.Replace(cfg("[b]", "{}"), `public_key: p }`+"\nusers", `public_key: p }`+"\n    hysteria2: { masquerade: https://example.com }\nusers", 1),
	} {
		_, err := build(t, ok, conventionalSecrets())
		require.NoError(t, err, name)
	}
}

// What a profile shows comes from the label, and each thing in it needs a
// name of its own: a label can make a member look like a group.
func TestBuild_Label(t *testing.T) {
	cfg := func(client string) string {
		return `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p, transports: { grpc: { service_name: g } } }
  b:
    address: b.example.com
    reality: { server_name: s, short_id: "2", public_key: p }
users:
  u: {}
  v: {}
client:
` + client
	}
	f, err := build(t, cfg("  groups: { proxy: { relay: all, default: a/reality-grpc@b } }\n"), map[string]any{
		"users": map[string]any{"u": "uuid-u", "v": "uuid-v"},
		"nodes": map[string]any{"a": map[string]any{"reality": "k"}, "b": map[string]any{"reality": "k"}},
	})
	require.NoError(t, err)
	u, _ := f.User("u")
	a, _ := f.Node("a")
	b, _ := f.Node("b")
	require.Equal(t, "a-reality-grpc", u.Client.Name(u, a, "reality-grpc"))
	require.Equal(t, "a-reality-grpc@b", Relayed(u.Client.Name(u, a, "reality-grpc"), b))
	require.Equal(t, "a/reality-grpc", MemberID(a, "reality-grpc"))
	require.Equal(t, "a/reality-grpc@b", Relayed(MemberID(a, "reality-grpc"), b))
	require.Equal(t, "u: a (reality)", (&Client{Label: "{user}: {node} ({protocol})"}).Name(u, a, "reality"))

	for client, want := range map[string]string{
		"  label: \"{node}\"\n":                   "client.label: needs {protocol}",
		"  label: \"{protocol}\"\n":               "client.label: needs {node}",
		"  label: \"{node} {protocol} {city}\"\n": "client.label: unknown field {city}; have {node}, {protocol}, {user}",
		"  label: \"{node}@{protocol}\"\n":        "client.label: can't have @",
		// One error, though both users share the client.
		"  groups: { a-reality-grpc: {} }\n":                                     `client.label: a/reality-grpc is named "a-reality-grpc", like group a-reality-grpc; rename the group or change the label`,
		"  groups: { b: { auto: true } }\n  label: \"b-auto{node}{protocol}\"\n": "",
		"  groups: { p: { auto: true } }\n  label: \"{node}-{protocol}\"\n":      "",
		"  label: \" {node} {protocol}\"\n":                                      "client.label: can't start or end with a space",
		// A default names a member the group has, for those with its nodes.
		"  groups: { proxy: { default: a-reality } }\n":                          `client.groups.proxy.default: want first, auto, direct or a member of the group such as fr/reality or fr/reality@ru; "a-reality" isn't <node>/<protocol>`,
		"  groups: { proxy: { default: c/reality } }\n":                          `"c/reality" names no node`,
		"  groups: { proxy: { default: a/reality } }\n":                          `"a/reality" is no protocol node a offers profiles (reality-grpc)`,
		"  groups: { proxy: { default: b/naive } }\n":                            `"b/naive" is no protocol node b offers profiles (reality)`,
		"  groups: { proxy: { nodes: none, default: b/reality } }\n":             `"b/reality" is of a node the group's nodes leave out`,
		"  groups: { proxy: { default: a/reality-grpc@b } }\n":                   `"a/reality-grpc@b" is through a node the group's relay leaves out`,
		"  groups: { proxy: { relay: all, default: a/reality-grpc@nowhere } }\n": `"a/reality-grpc@nowhere" names no relay node`,
		"  groups: { proxy: { relay: all, default: b/reality@b } }\n":            `"b/reality@b" is through the node itself`,
		"  groups: { proxy: { default: direct } }\n":                             "client.groups.proxy.default: direct needs include_direct: true",
		"  groups: { proxy: { include_direct: true, default: direct } }\n":       "",
		"  groups: { proxy: { relay: all, default: b/reality@a } }\n":            "",
	} {
		_, err := build(t, cfg(client), map[string]any{
			"users": map[string]any{"u": "uuid-u", "v": "uuid-v"},
			"nodes": map[string]any{"a": map[string]any{"reality": "k"}, "b": map[string]any{"reality": "k"}},
		})
		if want == "" {
			require.NoError(t, err, client)
			continue
		}
		require.ErrorContains(t, err, want, client)
		require.Equal(t, 1, strings.Count(err.Error(), want), client)
	}
}

// Names are checked for what each user is shown: a group the profile
// leaves out takes no name, a share link the profile has no member for
// still needs one of its own, and a user's own label counts for them.
func TestBuild_ProfileNames(t *testing.T) {
	cfg := func(label, users string) string {
		return `
nodes:
  fr:
    address: fr.example.com
    engine: xray
    tags: [x]
    reality: { server_name: s, short_id: "1", public_key: p, transports: { tcp: {}, xhttp: { path: /p } } }
  xhttp-fr:
    address: b.example.com
    reality: { server_name: s, short_id: "2", public_key: p }
users:
` + users + `
client:
  label: "` + label + `"
  groups:
    fr-reality: { nodes: "!x" }
    all: {}
`
	}
	sec := map[string]any{
		"users": map[string]any{"u": "uuid-u", "v": "uuid-v"},
		"nodes": map[string]any{"fr": map[string]any{"reality": "k"}, "xhttp-fr": map[string]any{"reality": "k"}},
	}
	// u has no node in group fr-reality, so nothing of u's is named like it.
	_, err := build(t, cfg("{node}-{protocol}", "  u: { nodes: [fr] }"), sec)
	require.NoError(t, err)
	// v has, and node fr too.
	_, err = build(t, cfg("{node}-{protocol}", "  u: { nodes: [fr] }\n  v: {}"), sec)
	require.ErrorContains(t, err, `client.label: fr/reality is named "fr-reality", like group fr-reality`)

	// Only a share link, as sing-box has no XHTTP, but named like another.
	_, err = build(t, cfg("{protocol}-{node}", "  u: {}"), sec)
	require.ErrorContains(t, err, `client.label: xhttp-fr/reality is named "reality-xhttp-fr", like fr/reality-xhttp`)

	// The user's own label is theirs to get right, and to fix it with.
	_, err = build(t, cfg("{node}-{protocol}", "  u: { nodes: [fr] }\n  v: { client: { label: \"{node} {protocol}\" } }"), sec)
	require.NoError(t, err)
	_, err = build(t, cfg("{node} {protocol}", "  v: { client: { label: \"{node}-{protocol}\" } }"), sec)
	require.ErrorContains(t, err, `users.v.client.label: fr/reality is named "fr-reality", like group fr-reality`)
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

func TestBuild_WarpReserved(t *testing.T) {
	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    egress: warp
    warp: { reserved: [1, 256] }
users:
  u: {}
`, conventionalSecrets())
	require.ErrorContains(t, err, "nodes.a.warp.reserved: want 3 bytes")
}

func TestBuild_WarpEndpoint(t *testing.T) {
	cfg := func(warp string) string {
		return `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    egress: warp
    warp: ` + warp + `
users:
  u: {}
`
	}

	f, err := build(t, cfg(`{ endpoint: "162.159.192.1:4500" }`), conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, "162.159.192.1", f.Nodes[0].Warp.Host)
	require.Equal(t, 4500, f.Nodes[0].Warp.Port)

	for _, bad := range []string{"162.159.192.1", ":4500", "example.com:0", "example.com:http", "example.com:65536", "bad host:4500", "-bad.example.com:4500"} {
		_, err := build(t, cfg(`{ endpoint: "`+bad+`" }`), conventionalSecrets())
		require.ErrorContains(t, err, "nodes.a.warp.endpoint: want host:port", bad)
	}
}

func TestBuild_EngineLimits(t *testing.T) {
	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
  b:
    address: b.example.com
    engine: xray
    hysteria2: { masquerade: https://example.com }
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
		"nodes.b.hysteria2: engine xray doesn't serve it",
		"nodes.b.dns.servers.dot: xray has no DNS over TLS",
		"nodes.b.rules[0]: xray doesn't route ICMP",
		"nodes.b.dns.rules[0].server: required",
		`nodes.c: engine "v2ray" is not supported (have: sing-box, xray)`,
	} {
		require.ErrorContains(t, err, want)
	}
}

func TestBuild_GroupAuto(t *testing.T) {
	f, err := build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: {}
client:
  groups:
    proxy: { nodes: all, auto: true }
  final: proxy
`, conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, "auto", f.Client.Groups[0].Default)

	_, err = build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: {}
client:
  groups:
    proxy: { nodes: all, auto: true }
    proxy-auto: { nodes: all }
    manual: { nodes: all, default: auto }
  final: proxy
`, conventionalSecrets())
	require.ErrorContains(t, err, "client.groups.proxy.auto: its member is named proxy-auto, like another group")
	require.ErrorContains(t, err, "client.groups.manual.default: auto needs auto: true")
}

func TestBuild_GroupRelay(t *testing.T) {
	src := func(relay string) string {
		return `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
  b: { address: b.example.com, tags: [near], reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: {}
client:
  groups:
    proxy: { nodes: "!near", relay: ` + relay + ` }
  final: proxy
`
	}
	f, err := build(t, src("near"), conventionalSecrets())
	require.NoError(t, err)
	a, _ := f.Node("a")
	b, _ := f.Node("b")
	require.True(t, f.Client.Groups[0].Relay.Matches(b))
	require.False(t, f.Client.Groups[0].Relay.Matches(a))

	_, err = build(t, src(`"!"`), conventionalSecrets())
	require.ErrorContains(t, err, `client.groups.proxy.relay: want <tag>, !<tag> or all, got "!"`)
	_, err = build(t, src("nowhere"), conventionalSecrets())
	require.ErrorContains(t, err, "client.groups.proxy.relay: no node with reality over a transport the profiles speak matches nowhere")

	f, err = build(t, strings.Replace(src("near"), ", relay: near", "", 1), conventionalSecrets())
	require.NoError(t, err)
	require.Nil(t, f.Client.Groups[0].Relay)
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

func TestBuild_RuleData(t *testing.T) {
	f, err := build(t, "", nil)
	require.NoError(t, err)
	require.Equal(t, "runetfreedom", f.RuleData.GeoIP.Preset)
	require.Equal(t, "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat", f.RuleData.Geosite.URL)
	require.NotEmpty(t, f.RuleData.Geosite.Nix.Hash, "pinned for NixOS")

	f, err = build(t, "rule_data: { geoip: dbip, geosite: https://example.org/geosite.dat }\n", nil)
	require.NoError(t, err)
	require.Equal(t, "dbip", f.RuleData.GeoIP.Preset)
	require.Equal(t, &NixSource{Package: "dbip-country-lite", Path: "share/dbip/dbip-country-lite.mmdb"}, f.RuleData.GeoIP.Nix)
	require.Equal(t, RuleSource{URL: "https://example.org/geosite.dat"}, f.RuleData.Geosite)

	_, err = build(t, "rule_data: { geoip: maxmind, geosite: dbip }\n", nil)
	require.ErrorContains(t, err, `rule_data.geoip: unknown preset "maxmind" (have: dbip, loyalsoldier, runetfreedom, v2fly; or an https:// URL)`)
	require.ErrorContains(t, err, "rule_data.geosite: preset dbip has no geosite data")
	_, err = build(t, "rule_data: http://example.org/geo.dat\n", nil)
	require.ErrorContains(t, err, `rule_data.geoip: "http://example.org/geo.dat" isn't an https:// URL`)
}

func TestBuild_Log(t *testing.T) {
	cfg := func(defaults, node, client string) string {
		return `
defaults: { ` + defaults + ` }
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    ` + node + `
  b:
    address: b.example.com
    reality: { server_name: s, short_id: "2", public_key: p }
users:
  u: {}
client: { ` + client + ` }
`
	}

	f, err := build(t, cfg("", "", ""), conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, LogWarn, f.Nodes[0].Log)
	require.Equal(t, LogWarn, f.Client.Log)

	f, err = build(t, cfg("log: info", "log: none", "log: error"), conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, LogNone, f.Nodes[0].Log, "a's own level")
	require.Equal(t, "info", f.Nodes[1].Log, "b inherits the default")
	require.Equal(t, "error", f.Client.Log)

	_, err = build(t, cfg("log: warning", "log: trace", "log: verbose"), conventionalSecrets())
	require.ErrorContains(t, err, `defaults.log: want one of debug, info, warn, error, none, got "warning"`)
	require.ErrorContains(t, err, `nodes.a.log: want one of debug, info, warn, error, none, got "trace"`)
	require.ErrorContains(t, err, `client.log: want one of debug, info, warn, error, none, got "verbose"`)
}

func TestBuild_UserClient(t *testing.T) {
	src := func(router string) string {
		return `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: {}
  r: { client: ` + router + ` }
client:
  groups:
    proxy: { nodes: all }
  final: proxy
`
	}
	values := conventionalSecrets()
	values["users"].(map[string]any)["r"] = "uuid-r"

	f, err := build(t, src("{ groups: { proxy: { auto: true } } }"), values)
	require.NoError(t, err)
	u, _ := f.User("u")
	require.Same(t, &f.Client, u.Client)
	require.Equal(t, "first", f.Client.Groups[0].Default)
	r, _ := f.User("r")
	require.Equal(t, "auto", r.Client.Groups[0].Default)
	require.Equal(t, "proxy", r.Client.Final)

	_, err = build(t, src("{ groups: { proxy: { default: auto } }, final: nowhere }"), values)
	require.ErrorContains(t, err, "users.r.client.groups.proxy.default: auto needs auto: true")
	require.ErrorContains(t, err, `users.r.client.final: want direct or a group, got "nowhere"`)
	require.NotContains(t, err.Error(), "\nclient.")
}

func TestBuild_UserClient_EveryOverrideChecked(t *testing.T) {
	values := conventionalSecrets()
	values["users"].(map[string]any)["v"] = "uuid-v"
	_, err := build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: { client: { final: nowhere } }
  v: { client: { final: nowhere } }
`, values)
	require.ErrorContains(t, err, "users.u.client.final")
	require.ErrorContains(t, err, "users.v.client.final")
}

func TestBuild_UserClient_BrokenClient(t *testing.T) {
	_, err := build(t, `
nodes:
  a: { address: a.example.com, reality: { server_name: s, short_id: "1", public_key: p } }
users:
  u: { client: { log: verbose } }
client:
  final: nowhere
`, conventionalSecrets())
	require.ErrorContains(t, err, `client.final: want direct or a group, got "nowhere"`)
	require.ErrorContains(t, err, `users.u.client.log: want one of`, "the override's own error")
	require.NotContains(t, err.Error(), "users.u.client.final", "not what it inherits")
}

func TestBuild_RealityTarget(t *testing.T) {
	node := func(reality, extra string) string {
		return "nodes:\n  a:\n    address: a.example.com\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p" + reality + " }\n" + extra
	}
	f, err := build(t, node("", ""), conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, "s.example.com", f.Nodes[0].Reality.TargetHost, "the server name by default")
	require.Equal(t, 443, f.Nodes[0].Reality.TargetPort)

	f, err = build(t, "defaults: { reality: { target: 127.0.0.1:8443 } }\n"+node("", ""), conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", f.Nodes[0].Reality.TargetHost, "from defaults")
	require.Equal(t, 8443, f.Nodes[0].Reality.TargetPort)

	for _, bad := range []string{"127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", ":8443", "bad_host:443"} {
		_, err = build(t, node(", target: \""+bad+"\"", ""), conventionalSecrets())
		require.ErrorContains(t, err, `nodes.a.reality.target: want host:port, e.g. 127.0.0.1:8443, got "`+bad+`"`)
	}
	label := strings.Repeat("a", 63)
	edge := strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".") // 253 characters
	_, err = build(t, node(", target: \""+edge+":443\"", ""), conventionalSecrets())
	require.NoError(t, err, "DNS allows 253 characters")
	long := strings.Join([]string{label, label, label, label}, ".") // 255 characters
	_, err = build(t, node(", target: \""+long+":443\"", ""), conventionalSecrets())
	require.ErrorContains(t, err, "nodes.a.reality.target: want host:port", "longer than DNS allows")
}

func TestBuild_RealityTargetLoopsBack(t *testing.T) {
	mux := "    naive: { domain: n.example.com }\n"
	for target, extra := range map[string]string{
		"127.0.0.1:443":     "",
		"[::1]:443":         "",
		"localhost:443":     "",
		"0.0.0.0:443":       "",
		"A.example.com:443": "",
		"127.0.0.1:8444":    mux,
		"a.example.com:443": mux,
	} {
		_, err := build(t, "nodes:\n  a:\n    address: a.example.com\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p, target: \""+target+"\" }\n"+extra, conventionalSecrets())
		require.ErrorContains(t, err, "nodes.a.reality.target: "+target+" is the node's own Reality listener", target)
	}
	for target, extra := range map[string]string{
		"127.0.0.1:8444":    "",
		"127.0.0.1:8443":    mux,
		"b.example.com:443": mux,
	} {
		_, err := build(t, "nodes:\n  a:\n    address: a.example.com\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p, target: \""+target+"\" }\n"+extra, conventionalSecrets())
		require.NoError(t, err, target)
	}
}

func TestBuild_RealityNameTakenByMux(t *testing.T) {
	for taken, extra := range map[string]string{
		"passthrough; drop that entry and set reality.target to 127.0.0.1:8443": "    passthrough: { S.Example.com: 127.0.0.1:8443 }\n",
		"naive; give one of them another name":                                  "    naive: { domain: s.example.com }\n",
		"the subscription site; give one of them another name":                  "subscription: { node: a, domains: [s.example.com] }\n",
	} {
		_, err := build(t, "nodes:\n  a:\n    address: a.example.com\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p }\n"+extra, conventionalSecrets())
		require.ErrorContains(t, err, "nodes.a.reality.server_name: the multiplexer sends s.example.com to "+taken, taken)
	}

	_, err := build(t, `
nodes:
  a:
    address: a.example.com
    reality: { server_name: a.example.com, short_id: "1", public_key: p, target: 127.0.0.1:8443 }
    passthrough: { site.example.com: 127.0.0.1:8443 }
`, conventionalSecrets())
	require.NoError(t, err, "self-steal: the node's own name, its site behind")
}

func TestBuild_SubscriptionDomains(t *testing.T) {
	const node = "nodes:\n  a:\n    address: a.example.com\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p }\n"
	f, err := build(t, node+"subscription: { node: a, domains: [New.example.com, old.example.org] }\n", conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, []string{"new.example.com", "old.example.org"}, f.Subscription.Domains)
	require.Equal(t, "new.example.com", f.Subscription.Domain())

	_, err = build(t, node+"subscription: { node: a, domains: [new.example.com, S.example.com] }\n", conventionalSecrets())
	require.ErrorContains(t, err, "nodes.a.reality.server_name: the multiplexer sends s.example.com to the subscription site", "every domain takes its name in the multiplexer")

	_, err = build(t, node+"subscription: { node: a }\n", conventionalSecrets())
	require.ErrorContains(t, err, "subscription.domains: required")

	// Names are checked whatever the node; a certificate needs a domain.
	_, err = build(t, node+"subscription: { node: b, domains: [new.example.com, New.example.com, \"bad name\", 192.0.2.1] }\n", conventionalSecrets())
	for _, want := range []string{
		`subscription.node: unknown node "b"`,
		"subscription.domains[1]: new.example.com: the site has it already",
		`subscription.domains[2]: "bad name" isn't a domain`,
		`subscription.domains[3]: "192.0.2.1" isn't a domain`,
	} {
		require.ErrorContains(t, err, want)
	}

	// The multiplexer can't send a name to the site and to passthrough.
	_, err = build(t, node+"    passthrough: { Old.example.org: 127.0.0.1:9443 }\n"+
		"subscription: { node: a, domains: [new.example.com, old.example.org] }\n", conventionalSecrets())
	require.ErrorContains(t, err, "subscription.domains[1]: old.example.org: nodes.a.passthrough sends it to 127.0.0.1:9443")

	// Nor to the site and to Naive, though the two may share a certificate.
	_, err = build(t, node+"    naive: { domain: Shop.example.com }\n"+
		"subscription: { node: a, domains: [shop.example.com] }\n", conventionalSecrets())
	require.ErrorContains(t, err, "subscription.domains[0]: shop.example.com: nodes.a.naive.domain takes it to Naive; give one of them another name")
}

// Profiles fetch their rule sets directly from a domain another node
// forwards to the site's node, through the proxy from the rest, unless
// subscription.domains says otherwise.
func TestBuild_SubscriptionRuleSets(t *testing.T) {
	nodes := func(siteAddress, target string) string {
		return "nodes:\n" +
			"  a:\n    address: " + siteAddress + "\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p }\n" +
			"  b:\n    address: b.example.ru\n    reality: { server_name: r.example.ru, short_id: \"2\", public_key: p }\n" +
			"    passthrough: { Relayed.example.com: \"" + target + "\" }\n"
	}
	const domains = "subscription: { node: a, domains: [own.example.com, relayed.example.com] }\n"

	f, err := build(t, nodes("a.example.com", "192.0.2.1:443")+domains, conventionalSecrets())
	require.NoError(t, err, "a named site node can't be checked against the target")
	b := f.nodes["b"]
	require.Equal(t, map[string]RuleSetFetch{
		"own.example.com":     {},
		"relayed.example.com": {Direct: true, Relay: b},
	}, f.Subscription.RuleSets)
	require.True(t, f.Subscription.RuleSetsDirect("Relayed.example.com"))
	require.False(t, f.Subscription.RuleSetsDirect("own.example.com"))
	require.False(t, f.Subscription.RuleSetsDirect("other.example.com"))
	require.False(t, (*Subscription)(nil).RuleSetsDirect("relayed.example.com"))

	_, err = build(t, nodes("192.0.2.1", "192.0.2.1:8443")+domains, conventionalSecrets())
	require.NoError(t, err, "the site's IP, on a port forwarded on the way")

	for target, why := range map[string]string{
		"192.0.2.99:443": "it sends it to 192.0.2.99:443",
		"127.0.0.1:443":  "it sends it to the node itself",
		"[::1]:443":      "it sends it to the node itself",
	} {
		_, err = build(t, nodes("192.0.2.1", target)+domains, conventionalSecrets())
		require.ErrorContains(t, err, "nodes.b.passthrough.Relayed.example.com: "+why+", not to node a, which serves the subscription site; if it reaches the site all the same, set subscription.domains[1].rule_sets to direct or proxy", target)
	}

	// Set, rule_sets is taken as it is, and the passthrough isn't checked.
	f, err = build(t, nodes("192.0.2.1", "127.0.0.1:443")+
		"subscription:\n  node: a\n  domains:\n    - { name: own.example.com, rule_sets: direct }\n    - { name: Relayed.example.com, rule_sets: proxy }\n", conventionalSecrets())
	require.NoError(t, err)
	require.Equal(t, map[string]RuleSetFetch{
		"own.example.com":     {Direct: true, Set: true},
		"relayed.example.com": {Set: true},
	}, f.Subscription.RuleSets)

	_, err = build(t, nodes("a.example.com", "192.0.2.1:443")+
		"subscription: { node: a, domains: [{ name: own.example.com, rule_sets: relay }] }\n", conventionalSecrets())
	require.ErrorContains(t, err, `subscription.domains[0].rule_sets: "relay": want direct or proxy`)

	_, err = config.Parse([]byte("princo: v1\nsubscription: { node: a, domains: [{ name: own.example.com, via: b }] }\n"))
	require.ErrorContains(t, err, "via", "a domain's fields are decoded strictly")
}

func TestBuild_Stats(t *testing.T) {
	values := conventionalSecrets()
	values["nodes"].(map[string]any)["a"].(map[string]any)["api"] = "stats-a"
	f, err := build(t, `
defaults: { stats: true }
nodes:
  a:
    address: a.example.com
    reality: { server_name: s.example.com, short_id: "1", public_key: p }
  b:
    address: b.example.com
    reality: { server_name: s.example.com, short_id: "1", public_key: p }
    stats: false
`, values)
	require.NoError(t, err)
	a, _ := f.Node("a")
	require.True(t, a.Stats)
	require.Equal(t, &API{Secret: "stats-a"}, a.API)
	b, _ := f.Node("b")
	require.False(t, b.Stats, "a node's own stats: false wins")

	cfg, err := config.Parse([]byte("princo: v1\nnodes:\n  a:\n    address: a.example.com\n    reality: {}\n    stats: true\n"))
	require.NoError(t, err)
	require.Contains(t, Secrets(cfg), SecretUse{Path: "nodes/a/api", Field: "nodes.a.stats", Kind: SecretPassword},
		"princo secret gen makes it")

	_, err = build(t, `
nodes:
  a:
    engine: xray
    address: a.example.com
    reality: { server_name: s.example.com, short_id: "1", public_key: p }
    stats: true
`, values)
	require.ErrorContains(t, err, "nodes.a.stats: engine xray doesn't report connections; only sing-box does")

	values["nodes"].(map[string]any)["a"].(map[string]any)["api"] = ""
	_, err = build(t, "nodes:\n  a:\n    address: a.example.com\n    reality: { server_name: s.example.com, short_id: \"1\", public_key: p }\n    stats: true\n", values)
	require.ErrorContains(t, err, "nodes.a.stats: the secret nodes/a/api is empty")
}

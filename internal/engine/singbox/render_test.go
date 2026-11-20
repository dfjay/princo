package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixture = "../../../testdata/fleet"

// TestGolden renders every node and user of the fixture fleet and compares
// against testdata/fleet/golden; run with -update to accept changes.
func TestGolden(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()
	for _, n := range f.Nodes {
		if n.Engine != e.Name() {
			continue
		}
		t.Run("server-"+n.Name, func(t *testing.T) {
			got, err := e.RenderServer(f, n.Name)
			require.NoError(t, err)
			golden(t, "server-"+n.Name+".json", got)
		})
	}
	for _, u := range f.Users {
		t.Run("client-"+u.Name, func(t *testing.T) {
			got, err := e.RenderClient(f, u.Name, engine.AnyPlatform, f.Subscription.Domain())
			require.NoError(t, err)
			golden(t, "client-"+u.Name+".json", got)
		})
	}
	// From the domain relay forwards: rule sets fetched directly.
	t.Run("client-alice-relayed", func(t *testing.T) {
		got, err := e.RenderClient(f, "alice", engine.AnyPlatform, "subs.example.org")
		require.NoError(t, err)
		golden(t, "client-alice-relayed.json", got)
	})
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(fixture, "golden", name)
	if *update {
		require.NoError(t, os.WriteFile(path, append(got, '\n'), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file; run go test -update")
	require.JSONEq(t, string(want), string(got))
}

func TestChain(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()

	relay := renderJSON(t, e.RenderServer, f, "relay")
	route := relay["route"].(map[string]any)
	require.Equal(t, map[string]any{"ip_is_private": true, "action": "reject"}, route["rules"].([]any)[4],
		"no resolve: domains go to de as they are")
	require.Equal(t, "de/reality", route["final"], "relay exits through de")
	upstream := relay["outbounds"].([]any)[0].(map[string]any)
	require.Equal(t, "de.example.com", upstream["server"])
	require.Equal(t, "755f7363-f3ff-4523-b419-f2e71e80e7fd", upstream["uuid"])

	de := renderJSON(t, e.RenderServer, f, "de")
	users := de["inbounds"].([]any)[0].(map[string]any)["users"].([]any)
	require.Contains(t, users, map[string]any{
		"name": "chain:relay",
		"uuid": "755f7363-f3ff-4523-b419-f2e71e80e7fd",
		"flow": "xtls-rprx-vision",
	}, "de accepts the relay hop")
}

// relay can't reach the monitor's channel, and reports through the nodes
// that can.
func TestMonitorVia(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()

	relay := renderJSON(t, e.RenderServer, f, "relay")
	inbounds := relay["inbounds"].([]any)
	require.Equal(t, map[string]any{
		"type": "socks", "tag": "monitor-in", "listen": "127.0.0.1", "listen_port": 8447.0,
		"users": []any{
			map[string]any{"username": "de", "password": "0c1d6a52-8e0b-4f6e-9d1c-3b7a5e2f4a61"},
			map[string]any{"username": "fi", "password": "0c1d6a52-8e0b-4f6e-9d1c-3b7a5e2f4a61"},
			map[string]any{"username": "us", "password": "0c1d6a52-8e0b-4f6e-9d1c-3b7a5e2f4a61"},
		},
	}, inbounds[len(inbounds)-1], "on loopback, and behind a password")
	rules := relay["route"].(map[string]any)["rules"].([]any)
	require.Equal(t, map[string]any{"inbound": []any{"monitor-in"}, "auth_user": []any{"de"}, "action": "route", "outbound": "monitor:de"}, rules[0],
		"before anything resolves or redirects it")
	require.Equal(t, map[string]any{"inbound": []any{"monitor-in"}, "action": "reject"}, rules[3], "and nowhere else")
	var hop map[string]any
	for _, o := range relay["outbounds"].([]any) {
		if o := o.(map[string]any); o["tag"] == "monitor:de" {
			hop = o
		}
	}
	require.Equal(t, "0c1d6a52-8e0b-4f6e-9d1c-3b7a5e2f4a61", hop["uuid"], "not as the chain hop, whose traffic is the users'")

	for _, name := range []string{"de", "us"} {
		up := renderJSON(t, e.RenderServer, f, name)
		require.Contains(t, up["inbounds"].([]any)[0].(map[string]any)["users"], map[string]any{
			"name": "monitor:relay", "uuid": "0c1d6a52-8e0b-4f6e-9d1c-3b7a5e2f4a61", "flow": "xtls-rprx-vision",
		})
		rules := up["route"].(map[string]any)["rules"].([]any)
		require.Equal(t, []any{
			map[string]any{"action": "resolve"},
			map[string]any{"ip_is_private": true, "action": "reject"},
			map[string]any{"auth_user": []any{"monitor:relay"}, "action": "route", "outbound": "direct"},
		}, rules[:3], name+": past WARP, but not into its own network")
		for _, in := range up["inbounds"].([]any) {
			require.NotEqual(t, "monitor-in", in.(map[string]any)["tag"], name+" reaches the channel itself")
		}
	}

	// A node named as an outbound's tag takes none.
	deNode, _ := f.Node("de")
	deNode.Name = "monitor-us"
	var tags []any
	for _, o := range renderJSON(t, e.RenderServer, f, "relay")["outbounds"].([]any) {
		tags = append(tags, o.(map[string]any)["tag"])
	}
	require.Equal(t, []any{"monitor-us/reality", "monitor:monitor-us", "monitor:fi", "monitor:us", "direct"}, tags)
	deNode.Name = "de"

	// A chained node resolves the reports' domains itself to send them direct.
	us, _ := f.Node("us")
	de, _ := f.Node("de")
	us.Egress = fleet.Egress{Kind: fleet.EgressNode, Node: de}
	rules = renderJSON(t, e.RenderServer, f, "us")["route"].(map[string]any)["rules"].([]any)
	require.Equal(t, map[string]any{"auth_user": []any{"monitor:relay"}, "action": "resolve"}, rules[0])
}

func TestMux(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()
	listenPort := func(node string) any {
		cfg := renderJSON(t, e.RenderServer, f, node)
		return cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"]
	}
	require.EqualValues(t, engine.MuxRealityPort, listenPort("de"), "de shares 443 with naive and a site")
	require.EqualValues(t, 443, listenPort("us"), "us has only reality")
}

func TestClientGroups(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()

	bob := renderJSON(t, client(e, engine.AnyPlatform), f, "bob")
	selectors := map[string][]any{}
	for _, ob := range bob["outbounds"].([]any) {
		ob := ob.(map[string]any)
		if ob["type"] == "selector" {
			selectors[ob["tag"].(string)] = ob["outbounds"].([]any)
		}
	}
	// us is offered through relay too, after the straight members.
	require.Equal(t, []any{"select-auto", "us-reality", "us-reality@relay"}, selectors["select"])
	require.Equal(t, []any{"direct", "relay-reality"}, selectors["ru-select"])
	// relay has no IPv6: refuse IPv6 to RU IPs before anything else, but
	// for what an earlier rule sends directly.
	first := bob["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	require.Equal(t, "reject", first["action"])
	require.Equal(t, true, first["no_drop"], "a burst of refusals must not turn into drops")
	require.Equal(t, []any{
		map[string]any{"ip_version": float64(6), "rule_set": []any{"geoip-ru"}},
		map[string]any{"type": "logical", "mode": "or", "invert": true, "rules": []any{
			map[string]any{"ip_is_private": true},
			map[string]any{"network": "icmp"},
		}},
	}, first["rules"])

	// alice can't reach relay, so ru-select falls back to direct.
	alice := renderJSON(t, client(e, engine.AnyPlatform), f, "alice")
	for _, ob := range alice["outbounds"].([]any) {
		require.NotEqual(t, "ru-select", ob.(map[string]any)["tag"])
	}

	// A default this user can't use gives way to the first member.
	f.Client.Groups[0].Default = "de/reality"
	bob = renderJSON(t, client(e, engine.AnyPlatform), f, "bob")
	for _, ob := range bob["outbounds"].([]any) {
		if ob := ob.(map[string]any); ob["tag"] == "select" {
			require.Equal(t, "us-reality", ob["default"])
		}
	}
}

// TestClientRelay offers a group's members through its relay nodes: inside
// the user's connection to the relay, as the user, over Reality.
func TestClientRelay(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()
	outbounds := func(user string) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, ob := range renderJSON(t, client(e, engine.AnyPlatform), f, user)["outbounds"].([]any) {
			ob := ob.(map[string]any)
			require.NotContains(t, out, ob["tag"], "an outbound twice")
			out[ob["tag"].(string)] = ob
		}
		return out
	}

	bob := outbounds("bob")
	relayed, straight := bob["us-reality@relay"], bob["us-reality"]
	require.Equal(t, "relay-reality", relayed["detour"])
	require.NotContains(t, straight, "detour")
	for _, k := range []string{"type", "server", "server_port", "uuid", "flow", "tls"} {
		require.Equal(t, straight[k], relayed[k], k)
	}

	// alice may not use relay: nothing of hers goes through it.
	for tag := range outbounds("alice") {
		require.NotContains(t, tag, "@")
	}

	// Every node relays every other one with Reality, never itself; a
	// member of two groups is one outbound.
	all := fleet.Selector{All: true}
	f.Client.Groups[0].Members, f.Client.Groups[0].Relay = all, &all
	f.Client.Groups[1].Members, f.Client.Groups[1].Relay = all, &all
	u, _ := f.User("bob")
	de, _ := f.Node("de")
	u.Nodes = append(u.Nodes, de)
	bob = outbounds("bob")
	require.Equal(t, []any{
		"select-auto",
		"us-reality", "relay-reality", "de-reality", "de-hysteria2", "de-naive",
		"relay-reality@us", "de-reality@us",
		"us-reality@relay", "de-reality@relay",
		"us-reality@de", "relay-reality@de",
	}, bob["select"]["outbounds"])
	require.Equal(t, "us-reality", bob["de-reality@us"]["detour"])
	require.Equal(t, "de.example.com", bob["de-reality@us"]["server"])
}

// TestSingBoxCheck runs `sing-box check` on everything rendered, with
// certificates and rule sets swapped for local stand-ins.
func TestSingBoxCheck(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		if os.Getenv("PRINCO_ENGINES") != "" {
			t.Fatal("sing-box not in PATH")
		}
		t.Skip("sing-box not in PATH")
	}
	dir := t.TempDir()
	cert, key := selfSignedCert(t, dir)
	ruleSet := emptyRuleSet(t, bin, dir)

	f := fleettest.Load(t, fixture)
	e := New()
	check := func(t *testing.T, cfg map[string]any) {
		walk(cfg, func(m map[string]any) {
			if _, ok := m["certificate_path"]; ok {
				m["certificate_path"], m["key_path"] = cert, key
			}
			if m["type"] == "local" && m["format"] == "binary" {
				m["path"] = ruleSet
			}
		})
		path := filepath.Join(dir, "config.json")
		data, err := json.Marshal(cfg)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		out, err := exec.CommandContext(t.Context(), bin, "check", "-c", path).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	for _, n := range f.Nodes {
		if n.Engine != e.Name() {
			continue
		}
		t.Run("server-"+n.Name, func(t *testing.T) { check(t, renderJSON(t, e.RenderServer, f, n.Name)) })
	}
	for _, u := range f.Users {
		t.Run("client-"+u.Name, func(t *testing.T) { check(t, renderJSON(t, client(e, engine.AnyPlatform), f, u.Name)) })
	}
	t.Run("client-relayed", func(t *testing.T) {
		check(t, renderJSON(t, func(f *fleet.Fleet, user string) ([]byte, error) {
			return e.RenderClient(f, user, engine.AnyPlatform, "subs.example.org")
		}, f, "alice"))
	})
	t.Run("client-published", func(t *testing.T) {
		f := fleettest.Load(t, fixture)
		f.Subscription.RuleSetURL = "https://static.example.net/princo/"
		check(t, renderJSON(t, client(e, engine.AnyPlatform), f, "alice"))
	})
	if runtime.GOOS == "linux" {
		t.Run("client-linux", func(t *testing.T) { check(t, renderJSON(t, client(e, engine.Linux), f, "bob")) })
	}
	t.Run("grpc", func(t *testing.T) {
		f := withGRPC(t)
		for _, n := range []string{"de", "us", "relay"} {
			check(t, renderJSON(t, e.RenderServer, f, n))
		}
		check(t, renderJSON(t, client(e, engine.AnyPlatform), f, "bob"))
	})
	for _, obfs := range []string{"salamander", "gecko"} {
		t.Run("obfs-"+obfs, func(t *testing.T) {
			f := withObfs(t, obfs)
			check(t, renderJSON(t, e.RenderServer, f, "de"))
			check(t, renderJSON(t, client(e, engine.AnyPlatform), f, "alice"))
		})
	}
}

// client renders profiles for p, in renderJSON's shape.
func client(e *Engine, p engine.Platform) func(*fleet.Fleet, string) ([]byte, error) {
	return func(f *fleet.Fleet, user string) ([]byte, error) {
		return e.RenderClient(f, user, p, f.Subscription.Domain())
	}
}

func TestClientOverride(t *testing.T) {
	e := New()
	f := fleettest.Load(t, fixture)
	bob, _ := f.User("bob")
	own := *bob.Client
	own.Final = "direct"
	bob.Client = &own

	final := func(user string) any {
		return renderJSON(t, client(e, engine.AnyPlatform), f, user)["route"].(map[string]any)["final"]
	}
	require.Equal(t, "direct", final("bob"), "bob's own profile")
	require.Equal(t, "select", final("alice"))
}

// Direct traffic has the IPv6 of the network the device is on: the profile
// refuses it IPv6 while the default interface has no global address,
// unless client.ipv6 settles it.
func TestClientDirectIPv6(t *testing.T) {
	e := New()
	f := fleettest.Load(t, fixture)
	alice, _ := f.User("alice")
	own := *alice.Client
	alice.Client = &own

	noIPv6 := map[string]any{"default_interface_address": []any{"2000::/3"}, "invert": true}
	geoip := map[string]any{"ip_version": float64(6), "rule_set": []any{"geoip-ru"}}
	aaaa := map[string]any{"query_type": []any{"AAAA"}, "rule_set": []any{"geosite-category-ru"}}
	all := func(action map[string]any, rules ...any) map[string]any {
		rule := map[string]any{"type": "logical", "mode": "and", "rules": rules}
		maps.Copy(rule, action)
		return rule
	}
	reject := map[string]any{"action": "reject", "no_drop": true}
	predefined := map[string]any{"action": "predefined"}
	sniff := map[string]any{"action": "sniff"}
	lookup := map[string]any{"action": "route", "rule_set": []any{"geosite-category-ru"}, "server": "ru-dns"}
	render := func() (route, dns []any) {
		cfg := renderJSON(t, client(e, engine.AnyPlatform), f, "alice")
		dns, _ = cfg["dns"].(map[string]any)["rules"].([]any)
		return cfg["route"].(map[string]any)["rules"].([]any), dns
	}

	// alice has no domestic node, so ru-select is direct. ip:private goes
	// directly too, but a network without global IPv6 may still route it.
	route, dns := render()
	require.Equal(t, []any{all(reject, noIPv6, geoip), sniff}, route[:2])
	require.Equal(t, []any{all(predefined, noIPv6, aaaa), lookup}, dns)

	// The same for action: direct, whichever server answers.
	own.Rules = slices.Clone(own.Rules)
	own.Rules[1].Action, own.Rules[1].Via = fleet.ActionDirect, ""
	d := *own.DNS
	d.Rules = nil
	own.DNS = &d
	route, dns = render()
	require.Equal(t, []any{all(reject, noIPv6, geoip), sniff}, route[:2])
	require.Equal(t, []any{all(predefined, noIPv6, aaaa)}, dns)

	// Everything else going directly gets no AAAA either. What an earlier
	// rule sends through nodes keeps its IPv6.
	own.Rules = append([]fleet.Rule{{
		Match: []fleet.Matcher{
			{Kind: fleet.MatchDomainSuffix, Value: "example.org"},
			{Kind: fleet.MatchIP, Value: "2001:db8::/32"},
			{Kind: fleet.MatchPort, Value: "22"},
		},
		Action: fleet.ActionVia, Via: "select",
	}}, own.Rules...)
	own.Final = "direct"
	but := func(bodies ...any) map[string]any {
		return map[string]any{"type": "logical", "mode": "or", "invert": true, "rules": bodies}
	}
	proxied := but(map[string]any{"domain_suffix": []any{"example.org"}})
	// Ahead of sniff the rule is known by its IPs and ports.
	proxiedIPs := but(map[string]any{"ip_cidr": []any{"2001:db8::/32"}}, map[string]any{"port": []any{float64(22)}})
	anyAAAA := map[string]any{"query_type": []any{"AAAA"}}
	route, dns = render()
	require.Equal(t, []any{all(reject, noIPv6, geoip, proxiedIPs), sniff}, route[:2])
	require.Equal(t, []any{all(predefined, noIPv6, aaaa, proxied), all(predefined, noIPv6, anyAAAA, proxied)}, dns)

	no, yes := false, true
	own.IPv6 = &no
	route, dns = render()
	require.Equal(t, []any{all(reject, geoip, proxiedIPs), sniff}, route[:2])
	require.Equal(t, []any{all(predefined, aaaa, proxied), all(predefined, anyAAAA, proxied)}, dns)

	own.IPv6 = &yes
	route, dns = render()
	require.Equal(t, sniff, route[0])
	require.Empty(t, dns)

	// A range sent directly may hold the network's own addresses, and
	// without client.dns the rules stand ahead of the app's own resolver.
	own.IPv6, own.DNS = nil, nil
	own.Rules = []fleet.Rule{{Match: []fleet.Matcher{{Kind: fleet.MatchIP, Value: "::/0"}}, Action: fleet.ActionDirect}}
	route, dns = render()
	everywhere := map[string]any{"ip_version": float64(6), "ip_cidr": []any{"::/0"}}
	require.Equal(t, all(reject, noIPv6, everywhere, but(map[string]any{"ip_is_private": true})), route[0])
	require.Equal(t, []any{all(predefined, noIPv6, anyAAAA)}, dns)
}

func TestClientPlatforms(t *testing.T) {
	e := New()
	f := fleettest.Load(t, fixture)
	tun := func(cfg map[string]any) map[string]any { return cfg["inbounds"].([]any)[0].(map[string]any) }
	require.Equal(t, true, tun(renderJSON(t, client(e, engine.Linux), f, "bob"))["auto_redirect"])
	require.NotContains(t, tun(renderJSON(t, client(e, engine.AnyPlatform), f, "bob")), "auto_redirect")
	_, err := e.RenderClient(f, "bob", "macos", "")
	require.ErrorContains(t, err, "sing-box has no profiles for macos")
}

// withObfs is the fixture fleet with de's Hysteria2 obfuscated.
func withObfs(t *testing.T, obfs string) *fleet.Fleet {
	t.Helper()
	f := fleettest.Load(t, fixture)
	de, _ := f.Node("de")
	de.Hysteria2 = &fleet.Hysteria2{Obfs: obfs, ObfsPassword: "obfs-password"}
	return f
}

func TestHysteria2Obfs(t *testing.T) {
	e := New()
	hysteria2 := func(cfg map[string]any, key string) map[string]any {
		for _, v := range cfg[key].([]any) {
			if v := v.(map[string]any); v["type"] == "hysteria2" {
				return v
			}
		}
		t.Fatalf("no hysteria2 in %s", key)
		return nil
	}

	f := fleettest.Load(t, fixture)
	in := hysteria2(renderJSON(t, e.RenderServer, f, "de"), "inbounds")
	require.NotContains(t, in, "obfs")
	require.Equal(t, "https://example.com", in["masquerade"].(map[string]any)["url"])
	require.NotContains(t, hysteria2(renderJSON(t, client(e, engine.AnyPlatform), f, "alice"), "outbounds"), "obfs")

	f = withObfs(t, "salamander")
	in = hysteria2(renderJSON(t, e.RenderServer, f, "de"), "inbounds")
	obfs := map[string]any{"type": "salamander", "password": "obfs-password"}
	require.Equal(t, obfs, in["obfs"])
	require.NotContains(t, in, "masquerade", "nothing reaches it through obfs")
	out := hysteria2(renderJSON(t, client(e, engine.AnyPlatform), f, "alice"), "outbounds")
	require.Equal(t, obfs, out["obfs"])
	require.Equal(t, "de-hysteria2", out["tag"])
}

func renderJSON(t *testing.T, render func(*fleet.Fleet, string) ([]byte, error), f *fleet.Fleet, name string) map[string]any {
	t.Helper()
	data, err := render(f, name)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// outboundsByTag indexes a rendered config's outbounds.
func outboundsByTag(t *testing.T, cfg map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, ob := range cfg["outbounds"].([]any) {
		ob := ob.(map[string]any)
		require.NotContains(t, out, ob["tag"], "an outbound twice")
		out[ob["tag"].(string)] = ob
	}
	return out
}

func walk(v any, visit func(map[string]any)) {
	switch v := v.(type) {
	case map[string]any:
		visit(v)
		for _, x := range v {
			walk(x, visit)
		}
	case []any:
		for _, x := range v {
			walk(x, visit)
		}
	}
}

func selfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func emptyRuleSet(t *testing.T, bin, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(src, []byte(`{"version": 3, "rules": []}`), 0o600))
	out := filepath.Join(dir, "empty.srs")
	msg, err := exec.CommandContext(t.Context(), bin, "rule-set", "compile", "-o", out, src).CombinedOutput()
	require.NoError(t, err, string(msg))
	return out
}

// withGRPC is the fixture with de, the chain's upstream, and us serving
// Reality over gRPC.
func withGRPC(t *testing.T) *fleet.Fleet {
	t.Helper()
	f := fleettest.Load(t, fixture)
	for _, name := range []string{"de", "us"} {
		n, _ := f.Node(name)
		n.Reality.Transports = []fleet.Transport{{Kind: fleet.TransportGRPC, ServiceName: "svc-" + name}}
	}
	return f
}

// Over gRPC there is no Vision flow, on either side, and whatever reaches
// the node takes the transport: apps, a chain hop, a relayed connection.
func TestRealityGRPC(t *testing.T) {
	f := withGRPC(t)
	e := New()
	grpc := func(node string) map[string]any {
		return map[string]any{"type": "grpc", "service_name": "svc-" + node}
	}

	de := renderJSON(t, e.RenderServer, f, "de")
	in := de["inbounds"].([]any)[0].(map[string]any)
	require.Equal(t, grpc("de"), in["transport"])
	require.Contains(t, in["users"], map[string]any{"name": "chain:relay", "uuid": "755f7363-f3ff-4523-b419-f2e71e80e7fd"})
	for _, u := range in["users"].([]any) {
		require.NotContains(t, u, "flow")
	}

	relay := renderJSON(t, e.RenderServer, f, "relay")
	require.Equal(t, "de/reality-grpc", relay["route"].(map[string]any)["final"])
	hop := relay["outbounds"].([]any)[0].(map[string]any)
	require.Equal(t, "de/reality-grpc", hop["tag"])
	require.Equal(t, grpc("de"), hop["transport"])
	require.NotContains(t, hop, "flow")
	in = relay["inbounds"].([]any)[0].(map[string]any)
	require.NotContains(t, in, "transport", "relay itself stays on tcp")
	require.Equal(t, "xtls-rprx-vision", in["users"].([]any)[0].(map[string]any)["flow"])

	reports := outboundsByTag(t, relay)["monitor:us"]
	require.Equal(t, grpc("us"), reports["transport"], "the monitor's reports take it too")
	require.NotContains(t, reports, "flow")
	us := renderJSON(t, e.RenderServer, f, "us")
	require.Contains(t, us["inbounds"].([]any)[0].(map[string]any)["users"],
		map[string]any{"name": "monitor:relay", "uuid": "0c1d6a52-8e0b-4f6e-9d1c-3b7a5e2f4a61"})

	bob := outboundsByTag(t, renderJSON(t, client(e, engine.AnyPlatform), f, "bob"))
	require.Equal(t, grpc("us"), bob["us-reality-grpc"]["transport"])
	require.NotContains(t, bob["us-reality-grpc"], "flow")
	require.NotContains(t, bob, "us-reality")
	require.Equal(t, "xtls-rprx-vision", bob["relay-reality"]["flow"])
	require.Equal(t, []any{"select-auto", "us-reality-grpc", "us-reality-grpc@relay"}, bob["select"]["outbounds"])
	require.Equal(t, "relay-reality", bob["us-reality-grpc@relay"]["detour"])
	require.Equal(t, grpc("us"), bob["us-reality-grpc@relay"]["transport"])
}

// The label names what the profile shows: members, relayed ones and what
// refers to them. princo.yaml goes on referring to a member by its ID.
func TestClientLabel(t *testing.T) {
	f := fleettest.Load(t, fixture)
	f.Client.Label = "{node} · {protocol}"
	f.Client.Groups[0].Default = "us/reality@relay"
	bob := outboundsByTag(t, renderJSON(t, client(New(), engine.AnyPlatform), f, "bob"))
	require.Equal(t, []any{"select-auto", "us · reality", "us · reality@relay"}, bob["select"]["outbounds"])
	require.Equal(t, "us · reality@relay", bob["select"]["default"])
	require.Equal(t, "relay · reality", bob["us · reality@relay"]["detour"])
	require.Equal(t, []any{"us · reality", "us · reality@relay"}, bob["select-auto"]["outbounds"])
	require.Equal(t, []any{"direct", "relay · reality"}, bob["ru-select"]["outbounds"])
	require.NotContains(t, bob, "us-reality")
}

// A relay that serves gRPC is the detour by it.
func TestRelayGRPC(t *testing.T) {
	f := fleettest.Load(t, fixture)
	relay, _ := f.Node("relay")
	relay.Reality.Transports = []fleet.Transport{{Kind: fleet.TransportGRPC, ServiceName: "svc"}}
	bob := outboundsByTag(t, renderJSON(t, client(New(), engine.AnyPlatform), f, "bob"))
	require.Equal(t, "relay-reality-grpc", bob["us-reality@relay"]["detour"])
	require.Equal(t, "xtls-rprx-vision", bob["us-reality@relay"]["flow"], "the member stays on tcp inside it")
	require.Contains(t, bob, "relay-reality-grpc")
}

// Every transport fleet lists for sing-box has its renderer, and one that
// hasn't is an error, not a config for another transport.
func TestTransportsRendered(t *testing.T) {
	for _, kind := range fleet.EngineTransports(engineName) {
		require.Contains(t, transports, kind)
	}
	e := New()
	for name, ts := range map[string][]fleet.Transport{
		"sing-box renders no reality transport \"xhttp\"": {{Kind: fleet.TransportXHTTP, Path: "/p"}},
		"sing-box serves one reality transport, got 0":    nil,
		"sing-box serves one reality transport, got 2":    {{Kind: fleet.TransportTCP}, {Kind: fleet.TransportGRPC}},
	} {
		f := fleettest.Load(t, fixture)
		us, _ := f.Node("us")
		us.Reality.Transports = ts
		_, err := e.RenderServer(f, "us")
		require.ErrorContains(t, err, "node us: "+name)
	}
	// de is where relay's chain goes, and one of those it reports through.
	f := fleettest.Load(t, fixture)
	de, _ := f.Node("de")
	de.Reality.Transports = []fleet.Transport{{Kind: fleet.TransportXHTTP, Path: "/p"}}
	_, err := e.RenderServer(f, "relay")
	require.ErrorContains(t, err, "node de: no reality transport sing-box connects by")
}

// A node that serves only what sing-box doesn't speak is in no group: its
// share links are all its users get.
func TestClientUndialable(t *testing.T) {
	f := fleettest.Load(t, fixture)
	fi, _ := f.Node("fi")
	fi.Reality.Transports = fi.Reality.Transports[1:]
	alice := outboundsByTag(t, renderJSON(t, client(New(), engine.AnyPlatform), f, "alice"))
	for tag := range alice {
		require.NotContains(t, tag, "fi-")
	}
	require.Equal(t, []any{"select-auto", "de-reality", "de-hysteria2", "de-naive", "us-reality"}, alice["select"]["outbounds"])
}

func TestRealityTarget(t *testing.T) {
	f := fleettest.Load(t, fixture)
	us, _ := f.Node("us")
	us.Reality.TargetHost, us.Reality.TargetPort = "127.0.0.1", 8443
	in := renderJSON(t, New().RenderServer, f, "us")["inbounds"].([]any)[0].(map[string]any)
	tls := in["tls"].(map[string]any)
	require.Equal(t, us.Reality.ServerName, tls["server_name"])
	require.Equal(t, map[string]any{"server": "127.0.0.1", "server_port": 8443.0}, tls["reality"].(map[string]any)["handshake"])
}

// A profile fetches its rule sets through the proxy, unless a relay
// serves the domain it is from: the relay is there to be reached directly,
// and the nodes behind the proxy may refuse its address.
func TestRuleSetDetour(t *testing.T) {
	e := New()
	f := fleettest.Load(t, fixture)
	detour := func(domain string) any {
		out, err := e.RenderClient(f, "alice", engine.AnyPlatform, domain)
		require.NoError(t, err)
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(out, &cfg))
		require.Equal(t, "rules-http", cfg["route"].(map[string]any)["default_http_client"])
		return cfg["http_clients"].([]any)[0].(map[string]any)["detour"]
	}
	require.Equal(t, "select", detour("subs.example.com"), "served by the site's node")
	// sing-box refuses a detour to an empty direct outbound.
	require.Nil(t, detour("subs.example.org"), "served through a relay")
	require.Equal(t, "select", detour(""), "from SagerNet's rule sets")
}

// Rule sets published outside the fleet are fetched from there directly,
// their host looked up without the proxy, whatever domain serves the
// profile; subscription.rule_sets.fetch decides otherwise, for the site's
// too.
func TestRuleSetOrigin(t *testing.T) {
	e := New()
	render := func(f *fleet.Fleet, domain string) (client map[string]any, urls []any, rules []any) {
		out, err := e.RenderClient(f, "alice", engine.AnyPlatform, domain)
		require.NoError(t, err)
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(out, &cfg))
		route := cfg["route"].(map[string]any)
		for _, rs := range route["rule_set"].([]any) {
			urls = append(urls, rs.(map[string]any)["url"])
		}
		return cfg["http_clients"].([]any)[0].(map[string]any), urls, route["rules"].([]any)
	}
	published := []any{"https://static.example.net/princo/geoip-ru.srs", "https://static.example.net/princo/geosite-category-ru.srs"}

	f := fleettest.Load(t, fixture)
	f.Subscription.RuleSetURL = "https://static.example.net/princo/"
	for _, domain := range f.Subscription.Domains {
		client, urls, rules := render(f, domain)
		require.Equal(t, map[string]any{"tag": "rules-http", "domain_resolver": "bootstrap-dns"}, client, domain)
		require.Equal(t, published, urls, domain)
		require.Equal(t, []string{"geoip-ru.srs", "geosite-category-ru.srs"}, e.ClientRuleSets(mustRender(t, e, f, domain)))
		// sing-box fetches them past the tunnel: no rule names the host.
		require.NotContains(t, fmt.Sprint(rules), "static.example.net", domain)
	}

	// A DNS rule naming the host chooses its server.
	f.Users[0].Client.DNS.Rules = append(f.Users[0].Client.DNS.Rules, fleet.DNSRule{
		Match:  []fleet.Matcher{{Kind: fleet.MatchDomainSuffix, Value: "example.net"}},
		Server: "ru-dns",
	})
	client, _, _ := render(f, "subs.example.com")
	require.Equal(t, "ru-dns", client["domain_resolver"])

	f = fleettest.Load(t, fixture)
	f.Subscription.RuleSetURL, f.Subscription.RuleSetFetch = "https://static.example.net/princo/", fleet.FetchProxy
	client, urls, _ := render(f, "subs.example.org")
	require.Equal(t, map[string]any{"tag": "rules-http", "detour": "select"}, client)
	require.Equal(t, published, urls)

	// The site's own, through the proxy from a domain reached directly,
	// whose profile still refreshes directly.
	f = fleettest.Load(t, fixture)
	f.Subscription.RuleSetFetch = fleet.FetchProxy
	client, urls, rules := render(f, "subs.example.org")
	require.Equal(t, map[string]any{"tag": "rules-http", "detour": "select"}, client)
	require.Equal(t, []any{"https://subs.example.org/rules/geoip-ru.srs", "https://subs.example.org/rules/geosite-category-ru.srs"}, urls)
	require.Contains(t, rules, any(map[string]any{"domain": []any{"subs.example.org"}, "action": "route", "outbound": "direct"}))

	f.Subscription.RuleSetFetch = fleet.FetchDirect
	client, _, _ = render(f, "subs.example.com")
	require.Equal(t, map[string]any{"tag": "rules-http", "domain_resolver": "bootstrap-dns"}, client)
}

func mustRender(t *testing.T, e *Engine, f *fleet.Fleet, domain string) []byte {
	t.Helper()
	out, err := e.RenderClient(f, "alice", engine.AnyPlatform, domain)
	require.NoError(t, err)
	return out
}

// A profile from a domain reached directly refreshes directly too, its
// name looked up without the proxy: a dead node would otherwise keep the
// app from the profile that replaces it.
func TestSiteDirect(t *testing.T) {
	e := New()
	render := func(f *fleet.Fleet, domain string) (route, dns []any) {
		out, err := e.RenderClient(f, "alice", engine.AnyPlatform, domain)
		require.NoError(t, err)
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(out, &cfg))
		return cfg["route"].(map[string]any)["rules"].([]any), cfg["dns"].(map[string]any)["rules"].([]any)
	}
	routeRule := map[string]any{"domain": []any{"subs.example.org"}, "action": "route", "outbound": "direct"}
	dnsRule := map[string]any{"domain": []any{"subs.example.org"}, "action": "route", "server": "bootstrap-dns"}

	f := fleettest.Load(t, fixture)
	route, dns := render(f, "SUBS.example.org")
	i := slices.IndexFunc(route, func(r any) bool { return r.(map[string]any)["action"] == "hijack-dns" })
	require.Equal(t, routeRule, route[i+1], "right after hijack-dns, ahead of the user's rules")
	require.Contains(t, dns, any(dnsRule))

	route, dns = render(f, "subs.example.com")
	require.NotContains(t, route, any(map[string]any{"domain": []any{"subs.example.com"}, "action": "route", "outbound": "direct"}), "served by the site's node")
	for _, r := range dns {
		require.NotContains(t, r, "domain")
	}

	// The server the user's own rules give the name, when it needs no
	// proxy; a rule by geosite, or one to a proxied server, gives none.
	alice, _ := f.User("alice")
	d := alice.Client.DNS
	rules := d.Rules
	named := func(match, server string) map[string]any {
		m, err := fleet.ParseMatcher(match)
		require.NoError(t, err)
		d.Rules = append([]fleet.DNSRule{{Match: []fleet.Matcher{m}, Server: server}}, rules...)
		_, dns := render(f, "subs.example.org")
		i := slices.IndexFunc(dns, func(r any) bool { return r.(map[string]any)["server"] != nil })
		return dns[i].(map[string]any)
	}
	dnsRule["server"] = "direct-dns"
	require.Equal(t, dnsRule, named("domain_suffix:example.org", "direct-dns"))
	require.Equal(t, dnsRule, named("domain_keyword:subs", "direct-dns"))
	dnsRule["server"] = "bootstrap-dns"
	require.Equal(t, dnsRule, named("domain_suffix:.subs.example.org", "direct-dns"), "subdomains only")
	require.Equal(t, dnsRule, named("domain:subs.example.org", "proxy-dns"), "through the proxy")
	d.Rules = rules

	// A server reached directly may still look its own name up through
	// the proxy.
	d.Servers = append([]fleet.DNSServer{{Name: "doh", Type: "https", Server: "dns.example.net", Resolver: "proxy-dns"}}, d.Servers...)
	_, dns = render(f, "subs.example.org")
	require.Contains(t, dns, any(dnsRule))
	d.DefaultResolver = "doh"
	dnsRule["server"] = "direct-dns"
	_, dns = render(f, "subs.example.org")
	require.Contains(t, dns, any(dnsRule), "the first that needs no proxy")

	// With every server behind the proxy, the app's lookup has nowhere
	// else to go; the route still skips the proxy.
	for i := range alice.Client.DNS.Servers {
		alice.Client.DNS.Servers[i].Via = "select"
	}
	route, dns = render(f, "subs.example.org")
	require.Contains(t, route, any(routeRule))
	require.NotContains(t, dns, any(dnsRule))
}

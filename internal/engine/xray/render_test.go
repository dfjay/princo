package xray

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
	"github.com/dfjay/princo/internal/secrets"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixture = "../../../testdata/fleet"

// TestGolden renders every xray node of the fixture fleet and compares
// against testdata/fleet/golden; run with -update to accept changes.
func TestGolden(t *testing.T) {
	f := fleettest.Load(t, fixture)
	e := New()
	for _, n := range xrayNodes(f) {
		t.Run("server-"+n.Name, func(t *testing.T) {
			got, err := e.RenderServer(f, n.Name)
			require.NoError(t, err)
			path := filepath.Join(fixture, "golden", "server-"+n.Name+".json")
			if *update {
				require.NoError(t, os.WriteFile(path, append(got, '\n'), 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "missing golden file; run go test -update")
			require.JSONEq(t, string(want), string(got))
		})
	}
}

func TestRuleSets(t *testing.T) {
	f := fleettest.Load(t, fixture)
	cfg, err := New().RenderServer(f, "fi")
	require.NoError(t, err)
	require.Equal(t, []string{"geoip.dat", "geosite.dat"}, New().RuleSets(cfg))
	require.Empty(t, New().RuleSets([]byte(`{"routing": {}}`)))
}

// TestXrayCheck runs `xray run -test` on every rendered node, with the
// geodata of xray's package.
func TestXrayCheck(t *testing.T) {
	bin, err := exec.LookPath("xray")
	if err != nil {
		if os.Getenv("PRINCO_ENGINES") != "" {
			t.Fatal("xray not in PATH")
		}
		t.Skip("xray not in PATH")
	}
	f := fleettest.Load(t, fixture)
	for _, n := range xrayNodes(f) {
		t.Run("server-"+n.Name, func(t *testing.T) {
			data, err := New().RenderServer(f, n.Name)
			require.NoError(t, err)
			require.True(t, json.Valid(data))
			path := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			out, err := exec.CommandContext(t.Context(), bin, "run", "-test", "-c", path).CombinedOutput()
			require.NoError(t, err, string(out))
		})
	}
}

// edgeFleet has what the fixture lacks: a UDP DNS server on its own port
// behind a DNS rule, and a user named like the chain hop into the node.
func edgeFleet(t *testing.T) *fleet.Fleet {
	t.Helper()
	cfg, err := config.Parse([]byte(`
princo: v1
nodes:
  a:
    address: a.example.com
    engine: xray
    reality: { server_name: s.example.com, short_id: "01", public_key: x1UdIXGj0boXzk96E0ZBwNxdTvF-YwsK4XGVqVhvfFc }
    egress: warp
    dns:
      servers:
        corp: { address: "udp://10.0.0.1:5353" }
        quad9: { address: https://dns.quad9.net }
      final: quad9
      strategy: prefer_ipv6
      rules:
        - { match: [domain_suffix:corp.example], server: corp }
  relay:
    address: relay.example.com
    reality: { server_name: s.example.com, short_id: "02", public_key: p }
    egress: a
users:
  chain-relay: { nodes: [a] }
`))
	require.NoError(t, err)
	f, err := fleet.Build(cfg, secrets.NewStore(map[string]any{
		"users": map[string]any{"chain-relay": "dbc5aca6-f0dd-416d-b30f-813754d72f99"},
		"nodes": map[string]any{
			"a": map[string]any{
				"reality": "WJcIvGK46S17DFQ3-QnhPr0P6hJ1QYZWZiFp7jUgzXk",
				"warp": map[string]any{
					"private_key": "aCzPQ1cG5D0b4rBW1ZJvXyeyqbPBJwe4ttkRwEeIvGs=",
					"ipv4":        "172.16.0.3/32",
					"ipv6":        "2606:4700:110:8000::3/128",
				},
			},
			"relay": map[string]any{"reality": "k", "chain": "755f7363-f3ff-4523-b419-f2e71e80e7fd"},
		},
	}))
	require.NoError(t, err)
	return f
}

func TestRenderServer_Edges(t *testing.T) {
	data, err := New().RenderServer(edgeFleet(t), "a")
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))

	dns := cfg["dns"].(map[string]any)
	require.Equal(t, []any{
		map[string]any{
			"address": "10.0.0.1", "port": 5353.0,
			"domains": []any{"domain:corp.example"}, "skipFallback": true, "finalQuery": true,
		},
		map[string]any{"address": "https+local://dns.quad9.net/dns-query"},
	}, dns["servers"])
	routing := cfg["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	require.Equal(t, map[string]any{"inboundTag": []any{dns["tag"]}, "outboundTag": "direct"}, rules[0],
		"the resolver's own queries skip the egress")
	require.NotContains(t, routing, "domainStrategy", "no IP rules to resolve for")

	warp := cfg["outbounds"].([]any)[0].(map[string]any)
	require.Equal(t, "ForceIPv6v4", warp["targetStrategy"])

	var emails []any
	for _, c := range cfg["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any) {
		emails = append(emails, c.(map[string]any)["email"])
	}
	require.Equal(t, []any{"chain-relay", "chain:relay"}, emails)

	if bin, err := exec.LookPath("xray"); err == nil {
		path := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(path, data, 0o600))
		out, err := exec.CommandContext(t.Context(), bin, "run", "-test", "-c", path).CombinedOutput()
		require.NoError(t, err, string(out))
	}
}

// fi takes relay's reports in the fixture; here it also sends its own
// through de and us.
func TestRenderServer_MonitorVia(t *testing.T) {
	f := fleettest.Load(t, fixture)
	fi, _ := f.Node("fi")
	de, _ := f.Node("de")
	us, _ := f.Node("us")
	fi.MonitorVia, fi.MonitorUUID = []*fleet.Node{de, us}, "11111111-2222-4333-8444-555555555555"
	data, err := New().RenderServer(f, "fi")
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))

	inbounds := cfg["inbounds"].([]any)
	require.Equal(t, map[string]any{
		"tag": "monitor-in", "listen": "127.0.0.1", "port": 8447.0, "protocol": "socks",
		"settings": map[string]any{"auth": "password", "udp": false, "accounts": []any{
			map[string]any{"user": "de", "pass": "11111111-2222-4333-8444-555555555555"},
			map[string]any{"user": "us", "pass": "11111111-2222-4333-8444-555555555555"},
		}},
	}, inbounds[len(inbounds)-1])
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	require.Equal(t, []any{
		map[string]any{"inboundTag": []any{"monitor-in"}, "user": []any{"de"}, "outboundTag": "monitor:de"},
		map[string]any{"inboundTag": []any{"monitor-in"}, "user": []any{"us"}, "outboundTag": "monitor:us"},
		map[string]any{"inboundTag": []any{"monitor-in"}, "outboundTag": "block"},
	}, rules[:3])
	outbounds := cfg["outbounds"].([]any)
	require.Equal(t, "warp", outbounds[0].(map[string]any)["tag"], "what no rule matches still leaves by the egress")
	hop := outbounds[len(outbounds)-1].(map[string]any)
	require.Equal(t, "monitor:us", hop["tag"])
	require.Equal(t, "11111111-2222-4333-8444-555555555555", hop["settings"].(map[string]any)["id"])
	xrayCheck(t, data)

	// And takes relay's, past its WARP.
	f = fleettest.Load(t, fixture)
	data, err = New().RenderServer(f, "fi")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &cfg))
	require.Equal(t, map[string]any{"user": []any{"monitor:relay"}, "outboundTag": "direct"}, cfg["routing"].(map[string]any)["rules"].([]any)[0])
	xrayCheck(t, data)
}

// xrayCheck has xray, when there is one, load config.
func xrayCheck(t *testing.T, config []byte) {
	t.Helper()
	if bin, err := exec.LookPath("xray"); err == nil {
		path := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(path, config, 0o600))
		out, err := exec.CommandContext(t.Context(), bin, "run", "-test", "-c", path).CombinedOutput()
		require.NoError(t, err, string(out))
	}
}

func xrayNodes(f *fleet.Fleet) []*fleet.Node {
	var out []*fleet.Node
	for _, n := range f.Nodes {
		if n.Engine == "xray" {
			out = append(out, n)
		}
	}
	return out
}

// ip:private needs no geoip data: its ranges are in the config.
func TestCompileMatch_Private(t *testing.T) {
	rules := compileMatch([]fleet.Matcher{{Kind: fleet.MatchIP, Value: "private"}}, "block")
	require.Len(t, rules, 1)
	ips := rules[0].(map[string]any)["ip"].([]string)
	require.Contains(t, ips, "10.0.0.0/8")
	require.Contains(t, ips, "fc00::/7")
	require.Empty(t, New().RuleSets([]byte(`{"ip": ["10.0.0.0/8"]}`)))
}

func TestRenderLog(t *testing.T) {
	require.Equal(t, map[string]any{"loglevel": "warning"}, renderLog(fleet.LogWarn))
	require.Equal(t, map[string]any{"loglevel": "debug"}, renderLog("debug"))
	require.Equal(t, map[string]any{"loglevel": "none", "access": "none"}, renderLog(fleet.LogNone))
}

func TestRealityTarget(t *testing.T) {
	f := fleettest.Load(t, fixture)
	fi, _ := f.Node("fi")
	fi.Reality.TargetHost, fi.Reality.TargetPort = "127.0.0.1", 8443
	data, err := New().RenderServer(f, "fi")
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))
	for _, in := range cfg["inbounds"].([]any) {
		if in := in.(map[string]any); in["tag"] == "vless-reality-in" {
			reality := in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
			require.Equal(t, "127.0.0.1:8443", reality["target"])
			require.Equal(t, []any{fi.Reality.ServerName}, reality["serverNames"])
			return
		}
	}
	t.Fatal("no reality inbound")
}

// Behind the multiplexer, Reality listens on loopback alone, for both
// families: the multiplexer connects as the client's.
func TestRenderServer_BehindMux(t *testing.T) {
	f := fleettest.Load(t, fixture)
	fi, _ := f.Node("fi")
	fi.Passthrough = []fleet.Passthrough{{Host: "example.com", Target: "127.0.0.1:8443"}}
	data, err := New().RenderServer(f, "fi")
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	require.Equal(t, "vless-reality-in", in["tag"])
	require.Equal(t, "::", in["listen"])
	require.EqualValues(t, fleet.MuxRealityPort, in["port"])
	require.Equal(t, map[string]any{"customSockopt": []any{map[string]any{
		"system": "linux", "network": "tcp", "level": "1", "opt": "25", "type": "str", "value": "lo",
	}}}, in["streamSettings"].(map[string]any)["sockopt"])

	if bin, err := exec.LookPath("xray"); err == nil && runtime.GOOS == "linux" {
		path := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(path, data, 0o600))
		cmd := exec.CommandContext(t.Context(), bin, "run", "-test", "-c", path)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Join("..", "..", "..", "testdata", "ruledata"))
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
}

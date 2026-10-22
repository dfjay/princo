package xray

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
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

func xrayNodes(f *fleet.Fleet) []*fleet.Node {
	var out []*fleet.Node
	for _, n := range f.Nodes {
		if n.Engine == "xray" {
			out = append(out, n)
		}
	}
	return out
}

package xray

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
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

func xrayNodes(f *fleet.Fleet) []*fleet.Node {
	var out []*fleet.Node
	for _, n := range f.Nodes {
		if n.Engine == "xray" {
			out = append(out, n)
		}
	}
	return out
}

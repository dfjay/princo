package deploy

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixture = "../../testdata/fleet"

func build(t *testing.T, node string) *bundle.Bundle {
	t.Helper()
	data, err := os.ReadFile(fixture + "/princo.yaml")
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)
	placeholders, err := fleet.Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err)
	p, err := host.NewPlan(placeholders, node, func(path string) string { return "sops:s.yaml#" + path })
	require.NoError(t, err)

	files, err := host.Files(fleettest.Load(t, fixture), node)
	require.NoError(t, err)
	ruleSets := map[string][]byte{}
	for _, f := range p.RuleSets {
		ruleSets[f] = []byte("SRS " + f)
	}
	b, err := Build(p, files, ruleSets)
	require.NoError(t, err)
	return b
}

// TestGolden compares each node's bundle against testdata/deploy/<node>:
// a listing of its directories, files and units, and the files princo
// deploy writes itself. Run with -update to accept changes.
func TestGolden(t *testing.T) {
	for _, node := range []string{"de", "us", "relay"} {
		t.Run(node, func(t *testing.T) {
			b := build(t, node)
			var listing strings.Builder
			for _, d := range b.Dirs {
				fmt.Fprintf(&listing, "dir  %04o %-8s %s\n", d.Mode, group(d.Group), d.Path)
			}
			for _, f := range b.Files {
				fmt.Fprintf(&listing, "file %04o %-8s %s\n", f.Mode, group(f.Group), f.Path)
				switch f.Path {
				case UnitFile, StreamConf, SiteConf:
					golden(t, node, filepath.Base(f.Path), f.Data)
				}
			}
			for _, u := range b.Units {
				fmt.Fprintf(&listing, "unit %s enable=%t reload=%t check=%q\n", u.Name, u.Enable, u.Reload, u.Check)
				for _, f := range u.Files {
					fmt.Fprintf(&listing, "  %s\n", f)
				}
			}
			golden(t, node, "bundle.txt", []byte(listing.String()))
		})
	}
}

func group(g string) string {
	if g == "" {
		return "root"
	}
	return g
}

func golden(t *testing.T, node, name string, got []byte) {
	t.Helper()
	path := filepath.Join("../../testdata/deploy", node, name)
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file; run go test -update")
	require.Equal(t, string(want), string(got), path)
}

func TestBuild_MissingRuleSet(t *testing.T) {
	p := &host.Plan{Node: "de", Engine: "sing-box", Config: "sing-box.json", RuleSets: []string{"geoip-ru.srs"}}
	_, err := Build(p, map[string][]byte{"sing-box.json": nil}, nil)
	require.ErrorContains(t, err, "rule set geoip-ru.srs is missing")
}

func TestBuild_UnknownEngine(t *testing.T) {
	_, err := Build(&host.Plan{Node: "de", Engine: "xray"}, nil, nil)
	require.ErrorContains(t, err, "can't run engine xray yet")
}

func TestReadRuleSets(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip-ru.srs"), []byte("SRS\x01"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite-x.srs"), []byte("<html>"), 0o644))

	got, err := ReadRuleSets(dir, "sing-box", []string{"geoip-ru.srs"})
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{"geoip-ru.srs": []byte("SRS\x01")}, got)

	_, err = ReadRuleSets(dir, "sing-box", []string{"geosite-x.srs"})
	require.ErrorContains(t, err, "isn't a sing-box rule set")
}

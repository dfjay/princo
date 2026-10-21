package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixture = "../../testdata/fleet"

// plan is node's plan, rendered files and stand-in rule sets.
func plan(t *testing.T, node string) (*host.Plan, map[string][]byte, map[string][]byte) {
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
	return p, files, ruleSets
}

func build(t *testing.T, node string) *bundle.Bundle {
	t.Helper()
	p, files, ruleSets := plan(t, node)
	b, err := Build(p, files, ruleSets, false)
	require.NoError(t, err)
	return b
}

// TestGolden compares each node's bundle against testdata/deploy/<node>:
// a listing of its directories, files and units, and the files princo
// deploy writes itself. Run with -update to accept changes.
func TestGolden(t *testing.T) {
	for _, node := range []string{"de", "us", "relay", "fi"} {
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
				case CertbotHook:
					golden(t, node, "certbot-hook", f.Data)
					require.NoError(t, exec.Command("sh", "-n", "-c", string(f.Data)).Run())
				}
			}
			for _, u := range b.Units {
				fmt.Fprintf(&listing, "unit %s reload=%t check=%q\n", u.Name, u.Reload, u.Check)
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

func TestBootstrap(t *testing.T) {
	p, _, _ := plan(t, "de")
	site := func(b *bundle.Bundle) string { return string(file(t, b, SiteConf)) }

	b, err := Bootstrap(p, []string{"subs.example.com"})
	require.NoError(t, err)
	require.True(t, b.Partial, "the rest of the node stays as it is")
	require.NotContains(t, site(b), "ssl", "the site waits for its certificate")
	require.Contains(t, site(b), "server_name subs.example.com;", "but its challenges are served")
	require.Equal(t, []string{"nginx.service"}, unitNames(b))
	require.Equal(t, []string{SiteConf}, b.Units[0].Files)
	require.NotNil(t, file(t, b, CertbotHook))

	b, err = Bootstrap(p, []string{"naive-de.example.com"})
	require.NoError(t, err)
	require.Contains(t, site(b), "listen 127.0.0.1:8443 ssl;", "the site has its certificate")
}

func file(t *testing.T, b *bundle.Bundle, path string) []byte {
	t.Helper()
	for _, f := range b.Files {
		if f.Path == path {
			return f.Data
		}
	}
	t.Fatalf("no %s in the bundle", path)
	return nil
}

func unitNames(b *bundle.Bundle) []string {
	var out []string
	for _, u := range b.Units {
		out = append(out, u.Name)
	}
	return out
}

func TestBuild_MuxRemoved(t *testing.T) {
	p, files, ruleSets := plan(t, "us")
	b, err := Build(p, files, ruleSets, true)
	require.NoError(t, err)
	require.Equal(t, "# Written by princo deploy; changes here are overwritten.\n# Node us has no multiplexer.\n", string(file(t, b, StreamConf)))
	require.Equal(t, []string{"nginx.service", "princo.service"}, unitNames(b), "nginx lets go of TCP 443 first")
	require.False(t, b.Units[0].Reload, "and is gone from it after a restart")

	p, files, ruleSets = plan(t, "de")
	b, err = Build(p, files, ruleSets, true)
	require.NoError(t, err)
	require.Contains(t, string(file(t, b, StreamConf)), "stream {")
	require.Equal(t, []string{"princo.service", "nginx.service"}, unitNames(b))
}

func TestBuild_MissingRuleSet(t *testing.T) {
	p := &host.Plan{Node: "de", Engine: "sing-box", Config: "sing-box.json", RuleSets: []string{"geoip-ru.srs"}}
	_, err := Build(p, map[string][]byte{"sing-box.json": nil}, nil, false)
	require.ErrorContains(t, err, "rule set geoip-ru.srs is missing")
}

func TestBuild_UnknownEngine(t *testing.T) {
	_, err := Build(&host.Plan{Node: "de", Engine: "v2ray"}, nil, nil, false)
	require.ErrorContains(t, err, "can't run engine v2ray yet")
}

func TestFetchRuleSets_Checksums(t *testing.T) {
	geoip := []byte("\x0a\x04\x0a\x02RU")
	sum := sha256.Sum256(geoip)
	published := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			_, _ = w.Write(geoip)
		case "/geoip.dat.sha256sum":
			_, _ = io.WriteString(w, published+"  geoip.dat\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := engines["xray"]
	e := old
	e.ruleSetURL = func(file string) string { return srv.URL + "/" + file }
	engines["xray"] = e
	t.Cleanup(func() { engines["xray"] = old })

	config := []byte(`{"ip": ["geoip:ru"]}`)
	got, err := RuleSets(t.Context(), srv.Client(), "", "xray", []string{"geoip.dat"}, config)
	require.NoError(t, err)
	require.Equal(t, geoip, got["geoip.dat"])

	published = strings.Repeat("0", 64)
	_, err = RuleSets(t.Context(), srv.Client(), "", "xray", []string{"geoip.dat"}, config)
	require.ErrorContains(t, err, "doesn't match")
}

func TestReadRuleSets(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip-ru.srs"), []byte("SRS\x01"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite-x.srs"), []byte("<html>"), 0o644))

	got, err := RuleSets(t.Context(), nil, dir, "sing-box", []string{"geoip-ru.srs"}, nil)
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{"geoip-ru.srs": []byte("SRS\x01")}, got)

	_, err = RuleSets(t.Context(), nil, dir, "sing-box", []string{"geosite-x.srs"}, nil)
	require.ErrorContains(t, err, "isn't a sing-box rule set")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("\x0a\x04\x0a\x02RU\x0a\x04\x0a\x02DE"), 0o644))
	got, err = RuleSets(t.Context(), nil, dir, "xray", []string{"geoip.dat"}, []byte(`{"ip": ["geoip:ru"]}`))
	require.NoError(t, err)
	require.Equal(t, []byte("\x0a\x04\x0a\x02RU"), got["geoip.dat"], "only what the config uses")
	_, err = RuleSets(t.Context(), nil, dir, "xray", []string{"geoip.dat"}, []byte(`{"ip": ["geoip:fr"]}`))
	require.ErrorContains(t, err, "it has no fr")
	got, err = RuleSets(t.Context(), nil, dir, "xray", []string{"geoip.dat"}, []byte(`{"ip": ["geoip:!de"]}`))
	require.NoError(t, err)
	require.Equal(t, []byte("\x0a\x04\x0a\x02DE"), got["geoip.dat"], "a negated code needs its entry")
	_, err = RuleSets(t.Context(), nil, dir, "xray", []string{"geosite-x.srs"}, nil)
	require.ErrorContains(t, err, "isn't a xray rule set")
}

func TestEngines_PinnedVersions(t *testing.T) {
	for name, e := range engines {
		eng, err := engine.Lookup(name)
		require.NoError(t, err)
		require.False(t, olderThan(e.version, eng.MinVersion()),
			"%s: princo deploy installs %s, older than the %s its configs need", name, e.version, eng.MinVersion())
	}
}

// olderThan compares dotted versions such as 1.14.3.
func olderThan(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func TestCertbotHook_SiteKeyStaysRoots(t *testing.T) {
	hook, err := certbotHook(&host.Plan{
		Certificates: []string{"de.example.com", "subs.example.com"},
		Subscription: &host.Site{Domain: "subs.example.com"},
	})
	require.NoError(t, err)
	require.Contains(t, string(hook), "'subs.example.com') unit=nginx.service group=root ;;")
	require.Contains(t, string(hook), "'de.example.com') unit=princo.service group=princo-engine ;;")
}

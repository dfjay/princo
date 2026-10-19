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
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
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
		t.Run("server-"+n.Name, func(t *testing.T) {
			got, err := e.RenderServer(f, n.Name)
			require.NoError(t, err)
			golden(t, "server-"+n.Name+".json", got)
		})
	}
	for _, u := range f.Users {
		t.Run("client-"+u.Name, func(t *testing.T) {
			got, err := e.RenderClient(f, u.Name)
			require.NoError(t, err)
			golden(t, "client-"+u.Name+".json", got)
		})
	}
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
	require.Equal(t, "de-reality", route["final"], "relay exits through de")
	upstream := relay["outbounds"].([]any)[0].(map[string]any)
	require.Equal(t, "de.example.com", upstream["server"])
	require.Equal(t, "755f7363-f3ff-4523-b419-f2e71e80e7fd", upstream["uuid"])

	de := renderJSON(t, e.RenderServer, f, "de")
	users := de["inbounds"].([]any)[0].(map[string]any)["users"].([]any)
	require.Contains(t, users, map[string]any{
		"name": "chain-relay",
		"uuid": "755f7363-f3ff-4523-b419-f2e71e80e7fd",
		"flow": "xtls-rprx-vision",
	}, "de accepts the relay hop")
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

	bob := renderJSON(t, e.RenderClient, f, "bob")
	selectors := map[string][]any{}
	for _, ob := range bob["outbounds"].([]any) {
		ob := ob.(map[string]any)
		if ob["type"] == "selector" {
			selectors[ob["tag"].(string)] = ob["outbounds"].([]any)
		}
	}
	require.Equal(t, []any{"us-reality"}, selectors["select"])
	require.Equal(t, []any{"direct", "relay-reality"}, selectors["ru-select"])
	// relay has no IPv6: refuse IPv6 to RU IPs before anything else.
	first := bob["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	require.EqualValues(t, 6, first["ip_version"])
	require.Equal(t, "reject", first["action"])

	// alice can't reach relay, so ru-select falls back to direct.
	alice := renderJSON(t, e.RenderClient, f, "alice")
	for _, ob := range alice["outbounds"].([]any) {
		require.NotEqual(t, "ru-select", ob.(map[string]any)["tag"])
	}
}

// TestSingBoxCheck runs `sing-box check` on everything rendered, with
// certificates and rule sets swapped for local stand-ins.
func TestSingBoxCheck(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
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
		t.Run("server-"+n.Name, func(t *testing.T) { check(t, renderJSON(t, e.RenderServer, f, n.Name)) })
	}
	for _, u := range f.Users {
		t.Run("client-"+u.Name, func(t *testing.T) { check(t, renderJSON(t, e.RenderClient, f, u.Name)) })
	}
}

func renderJSON(t *testing.T, render func(*fleet.Fleet, string) ([]byte, error), f *fleet.Fleet, name string) map[string]any {
	t.Helper()
	data, err := render(f, name)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
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

package host

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
	"github.com/dfjay/princo/internal/secrets"
	"github.com/dfjay/princo/internal/subscription"
)

const fixture = "../../testdata/fleet"

func placeholderFleet(t *testing.T) *fleet.Fleet {
	t.Helper()
	data, err := os.ReadFile(fixture + "/princo.yaml")
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)
	f, err := fleet.Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err)
	return f
}

func plan(t *testing.T, node string) *Plan {
	t.Helper()
	p, err := NewPlan(placeholderFleet(t), node, func(path string) string { return "sops:s.yaml#" + path })
	require.NoError(t, err)
	return p
}

func secretPaths(p *Plan) []string {
	var out []string
	for _, s := range p.Secrets {
		out = append(out, s.Path)
	}
	return out
}

func TestPlan_Mux(t *testing.T) {
	p := plan(t, "de")
	require.Equal(t, "sing-box.json", p.Config)
	require.Equal(t, []int{443}, p.TCPPorts)
	require.Equal(t, []int{443}, p.UDPPorts)
	require.Equal(t, &Mux{
		Port: 443,
		Routes: []Route{
			{SNI: "example.com", Target: "127.0.0.1:8443"},
			{SNI: "subs.example.com", Target: SiteAddr},
			{SNI: "naive-de.example.com", Target: "127.0.0.1:8445"},
		},
		Default: "127.0.0.1:8444",
	}, p.Mux)
	require.Equal(t, []string{"de.example.com", "naive-de.example.com", "subs.example.com"}, p.Certificates)
	require.Equal(t, []string{"geoip-ru.srs", "geosite-category-ru.srs"}, p.RuleSets)
	require.Equal(t, &Site{Domain: "subs.example.com", Root: "subscription", Listen: SiteAddr}, p.Subscription)
	// Its own keys, the chain hop exiting here, and every user for the site.
	require.Equal(t, []string{
		"nodes/de/reality", "nodes/de/warp/ipv4", "nodes/de/warp/ipv6", "nodes/de/warp/private_key",
		"nodes/relay/chain", "users/alice", "users/bob",
	}, secretPaths(p))
	require.Equal(t, Source{Type: "sops", File: "s.yaml", Key: "users/alice"}, p.Secrets[5].Source)
}

func TestPlan_SiteSharesEngineCertificate(t *testing.T) {
	f := placeholderFleet(t)
	f.Subscription.Domain = "de.example.com"
	_, err := NewPlan(f, "de", func(path string) string { return "sops:s.yaml#" + path })
	require.ErrorContains(t, err, "subscription.domain: node de's engine has a certificate for de.example.com too")
}

func TestPlan_RealityOnly(t *testing.T) {
	p := plan(t, "us")
	require.Equal(t, []int{443}, p.TCPPorts)
	require.Empty(t, p.UDPPorts)
	require.Nil(t, p.Mux)
	require.Nil(t, p.Subscription)
	require.Empty(t, p.Certificates)
	require.Equal(t, []string{"nodes/us/reality", "users/alice", "users/bob"}, secretPaths(p))

	relay := plan(t, "relay")
	require.Equal(t, []string{"nodes/relay/chain", "nodes/relay/reality", "users/bob"}, secretPaths(relay))
}

func TestFiles_Subscription(t *testing.T) {
	f := fleettest.Load(t, fixture)
	files, err := Files(f, "de")
	require.NoError(t, err)

	alice, _ := f.User("alice")
	token := subscription.Token(alice)
	require.Len(t, token, 32)
	require.Contains(t, string(files[TokensFile]), "alice "+token+"\n")

	links, err := base64.StdEncoding.DecodeString(string(files["subscription/"+token+"/base64"]))
	require.NoError(t, err)
	require.Equal(t, strings.Join(subscription.URIs(alice), "\n"), string(links))
	require.Contains(t, string(files["subscription/"+token+"/sing-box/config"]), alice.UUID)
	page := string(files["subscription/"+token+"/index.html"])
	require.Contains(t, page, `href="sing-box://import-remote-profile?url=https%3A%2F%2Fsubs.example.com%2F`+token+`%2Fsing-box#alice"`)
	require.Contains(t, string(files["subscription/"+token+"/qr-sub.svg"]), "<svg")

	us, err := Files(f, "us")
	require.NoError(t, err)
	require.Len(t, us, 1, "only the subscription node gets the site")
	require.Contains(t, us, "sing-box.json")
}

func TestPlan_Xray(t *testing.T) {
	p := plan(t, "fi")
	require.Equal(t, "xray", p.Engine)
	require.Equal(t, "xray.json", p.Config)
	require.Equal(t, []int{443}, p.TCPPorts)
	require.Empty(t, p.UDPPorts)
	require.Nil(t, p.Mux)
	require.Empty(t, p.Certificates)
	require.Equal(t, []string{"geoip.dat", "geosite.dat"}, p.RuleSets)
	require.Equal(t, []string{
		"nodes/fi/reality", "nodes/fi/warp/ipv4", "nodes/fi/warp/ipv6", "nodes/fi/warp/private_key", "users/alice",
	}, secretPaths(p))
}

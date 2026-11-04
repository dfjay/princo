package host

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/certtest"
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
	p, err := NewPlan(placeholderFleet(t), node, func(path string) (string, int) { return "sops:s.yaml#" + path, 0 })
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
	require.Equal(t, []Certificate{
		{Name: "de.example.com", Domains: []string{"de.example.com"}, Source: fleet.CertHTTP},
		{Name: "naive-de.example.com", Domains: []string{"naive-de.example.com"}, Source: fleet.CertHTTP},
		{Name: "subs.example.com", Domains: []string{"subs.example.com"}, Source: fleet.CertHTTP, Site: true},
	}, p.Certificates)
	require.Equal(t, []string{"geoip-ru.srs", "geosite-category-ru.srs"}, p.RuleSets)
	require.Equal(t, "runetfreedom", p.RuleData.GeoIP.Preset)
	require.Equal(t, &Site{Domain: "subs.example.com", Certificate: "subs.example.com", Root: "subscription", Listen: SiteAddr}, p.Subscription)
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
	_, err := NewPlan(f, "de", func(path string) (string, int) { return "sops:s.yaml#" + path, 0 })
	require.ErrorContains(t, err, "subscription.domain: node de's engine has certificate de.example.com too, which it can't share with the web server")
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
	require.Contains(t, string(files["subscription/"+token+"/sing-box/linux/config"]), `"auto_redirect": true`)
	require.NotContains(t, string(files["subscription/"+token+"/sing-box/config"]), "auto_redirect")
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

// An xray node serving the subscription keeps the client profiles' rule
// sets beside its own, apart from what the engine loads.
func TestPlan_XraySubscription(t *testing.T) {
	data, err := os.ReadFile(fixture + "/princo.yaml")
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)
	cfg.Subscription.Node = "fi"
	f, err := fleet.Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err)
	p, err := NewPlan(f, "fi", func(path string) (string, int) { return "sops:s.yaml#" + path, 0 })
	require.NoError(t, err)
	require.Equal(t, []string{"geoip.dat", "geosite.dat"}, p.RuleSets)
	require.Equal(t, []string{"geoip-ru.srs", "geosite-category-ru.srs"}, p.SiteRuleSets)
}

func TestCertificates(t *testing.T) {
	chain, key := certtest.SelfSigned(t, "subs.example.com")
	cfg, err := config.Parse([]byte(`princo: v1
nodes:
  a:
    address: a.example.com
    hysteria2: { masquerade: https://www.example.org }
    naive: { domain: shop.example.com }
users:
  u: {}
subscription: { node: a, domain: subs.example.com }
certificates:
  wild:
    domains: ["*.example.com"]
    acme: { dns: cloudflare, env: { CLOUDFLARE_DNS_API_TOKEN: !secret cf } }
  site:
    domains: [subs.example.com]
    file: {}
`))
	require.NoError(t, err)
	values := map[string]any{
		"cf":           "token",
		"users":        map[string]any{"u": "uuid"},
		"shared":       map[string]any{"hysteria2_obfs": "obfs"},
		"certificates": map[string]any{"site": map[string]any{"fullchain": chain, "key": key}},
	}
	f, err := fleet.Build(cfg, secrets.NewStore(values))
	require.NoError(t, err)
	files, err := Files(f, "a")
	require.NoError(t, err)
	require.Equal(t, "CLOUDFLARE_DNS_API_TOKEN='token'\n", string(files["certificates/wild/dns.env"]))
	require.Equal(t, chain, string(files["certificates/site/fullchain.pem"]))
	require.Equal(t, key, string(files["certificates/site/key.pem"]))
	require.Contains(t, string(files["sing-box.json"]), `"/var/lib/princo/certs/wild/fullchain.pem"`, "one wildcard for hysteria2 and naive")
	require.NotContains(t, string(files["sing-box.json"]), "/certs/a.example.com/")

	placeholders, err := fleet.Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err)
	p, err := NewPlan(placeholders, "a", func(path string) (string, int) { return "sops:s.yaml#" + path, 0 })
	require.NoError(t, err)
	require.Equal(t, []Certificate{
		{Name: "site", Domains: []string{"subs.example.com"}, Source: fleet.CertFile, Site: true},
		{Name: "wild", Domains: []string{"*.example.com"}, Source: fleet.CertDNS, DNS: "cloudflare"},
	}, p.Certificates)
	require.Equal(t, "site", p.Subscription.Certificate)
	require.Subset(t, secretPaths(p), []string{"cf", "certificates/site/fullchain", "certificates/site/key"})

	cfg.Subscription.Domain = "subs2.example.com" // under the wildcard too
	placeholders, err = fleet.Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err)
	_, err = NewPlan(placeholders, "a", func(path string) (string, int) { return "", 0 })
	require.ErrorContains(t, err, "subscription.domain: node a's engine has certificate wild too")
}

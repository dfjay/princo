package deploy

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/certtest"
	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

// certPlan is a node with a DNS-01 wildcard for its engine and a
// certificate from files for its subscription site.
func certPlan(t *testing.T) (*host.Plan, map[string][]byte) {
	t.Helper()
	chain, key := certtest.SelfSigned(t, "subs.example.com")
	cfg, err := config.Parse([]byte(`princo: v1
nodes:
  a:
    address: a.example.com
    acme_email: ops@example.com
    hysteria2: { masquerade: https://www.example.org }
    naive: { domain: shop.example.com }
users:
  u: {}
subscription: { node: a, domains: [subs.example.com] }
certificates:
  wild:
    domains: [example.com, "*.example.com"]
    acme: { dns: cloudflare, env: { CLOUDFLARE_DNS_API_TOKEN: !secret cf } }
  site:
    domains: [subs.example.com]
    file: {}
`))
	require.NoError(t, err)
	f, err := fleet.Build(cfg, secrets.NewStore(map[string]any{
		"cf":           "token",
		"users":        map[string]any{"u": "uuid"},
		"shared":       map[string]any{"hysteria2_obfs": "obfs"},
		"certificates": map[string]any{"site": map[string]any{"fullchain": chain, "key": key}},
	}))
	require.NoError(t, err)
	files, err := host.Files(f, "a")
	require.NoError(t, err)
	placeholders, err := fleet.Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err)
	p, err := host.NewPlan(placeholders, "a", func(path string) (string, int) { return "sops:s.yaml#" + path, 0 })
	require.NoError(t, err)
	return p, files
}

func dir(t *testing.T, b *bundle.Bundle, p string) bundle.Dir {
	t.Helper()
	for _, d := range b.Dirs {
		if d.Path == p {
			return d
		}
	}
	t.Fatalf("no dir %s in the bundle", p)
	return bundle.Dir{}
}

func bundleFile(t *testing.T, b *bundle.Bundle, p string) bundle.File {
	t.Helper()
	for _, f := range b.Files {
		if f.Path == p {
			return f
		}
	}
	t.Fatalf("no %s in the bundle", p)
	return bundle.File{}
}

func TestBuild_Certificates(t *testing.T) {
	p, files := certPlan(t)
	b, err := Build(p, files, nil, Earlier{})
	require.NoError(t, err)

	site := path.Join(engine.CertDir, "site")
	require.Equal(t, bundle.Dir{Path: engine.CertDir, Mode: 0o750, Group: engineGroup}, dir(t, b, engine.CertDir))
	require.Equal(t, bundle.Dir{Path: site, Mode: 0o750}, dir(t, b, site), "nginx reads it as root")
	key := bundleFile(t, b, site+"/key.pem")
	require.Equal(t, files["certificates/site/key.pem"], key.Data)
	require.Equal(t, "", key.Group)
	require.EqualValues(t, 0o640, key.Mode)
	for _, f := range b.Files {
		require.NotEqual(t, path.Join(FilesDir, "certificates/site/key.pem"), f.Path, "not twice")
	}
	env := bundleFile(t, b, path.Join(FilesDir, "certificates/wild/dns.env"))
	require.Equal(t, "CLOUDFLARE_DNS_API_TOKEN='token'\n", string(env.Data))
	require.EqualValues(t, 0o600, env.Mode)

	require.Equal(t, []string{"princo.service", "princo-loopback.service", "nginx.service", "princo-lego.timer"}, unitNames(b))
	require.Contains(t, b.Units[2].Files, site+"/fullchain.pem", "nginx reloads on a new certificate")
	require.NotContains(t, string(bundleFile(t, b, SiteConf).Data), "acme-challenge", "nothing over HTTP-01 but the site's redirect")
	require.Contains(t, string(bundleFile(t, b, SiteConf).Data), "ssl_certificate /var/lib/princo/certs/site/fullchain.pem;")

	script := string(bundleFile(t, b, LegoScript).Data)
	require.NoError(t, exec.Command("sh", "-n", "-c", script).Run())
	require.Contains(t, script, `'/usr/local/lib/princo-lego/lego-`+lego.version+`/lego' run --path /var/lib/princo/lego --accept-tos --email 'ops@example.com' \
			--dns 'cloudflare' --env-file '/var/lib/princo/files/certificates/wild/dns.env' \
			--cert.name 'wild' --domains 'example.com' --domains '*.example.com' --force-cert-domains \
			--deploy-hook /etc/letsencrypt/renewal-hooks/deploy/princo || status=1
		restore 'wild' || status=1`)
	hook := string(bundleFile(t, b, CertbotHook).Data)
	require.Contains(t, hook, "'wild') units='princo.service' group=princo-engine ;;")
	require.NotContains(t, hook, "'site'")
}

func TestBootstrap_Certificates(t *testing.T) {
	p, files := certPlan(t)
	b, err := Bootstrap(p, files, []string{"wild"})
	require.NoError(t, err)
	bundleFile(t, b, path.Join(FilesDir, "certificates/wild/dns.env"))
	bundleFile(t, b, LegoScript)
	bundleFile(t, b, path.Join(engine.CertDir, "site/key.pem"))
	require.Contains(t, string(bundleFile(t, b, SiteConf).Data), "ssl", "the site has its certificate already")
	require.Equal(t, []string{"nginx.service"}, unitNames(b), "the timer waits for the full bundle")
}

func TestDeploy_DNSCertificate(t *testing.T) {
	p, files := certPlan(t)
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nlego\nprinco 0.2.0\nmonitor\nmissing wild\n"}
	d, _ := newDeployer(r, "0.2.0")
	require.NoError(t, d.Deploy(t.Context(), p, files, nil))
	require.Equal(t, []string{"probe", "provision", "apply", "issue wild", "apply", "prune"}, r.steps)

	var script string
	d.Remote = remoteFunc(func(s string) { script = s })
	require.NoError(t, d.provision(t.Context(), p))
	require.Contains(t, script, "for p in 'nginx' 'libnginx-mod-stream' 'iproute2' 'openssl'; do", "no certbot")
	require.Equal(t, []string{"allow 443/tcp comment princo", "allow 443/udp comment princo"}, runUFW(t, script, ""), "nor port 80")

	_, _ = d.probe(t.Context(), p)
	require.Contains(t, script, "echo missing 'wild'")
	require.NotContains(t, script, "echo missing 'site'", "it comes with the bundle")
}

func TestProbe_CertificateDomains(t *testing.T) {
	p, _ := certPlan(t)
	for sans, missing := range map[string]bool{
		"DNS:*.example.com,DNS:example.com":                     false,
		"DNS:Example.com,DNS:*.example.com":                     false,
		"DNS:example.com":                                       true,
		"DNS:example.com,DNS:*.example.com,DNS:old.example.org": true,
	} {
		d, _ := newDeployer(&fakeRemote{t: t, probe: "arch amd64\nsans wild " + sans + "\n"}, "0.2.0")
		f, err := d.probe(t.Context(), p)
		require.NoError(t, err)
		require.Equal(t, missing, slices.Contains(f.missing, "wild"), sans)
	}
}

func TestBuild_DNSCertificateAlone(t *testing.T) {
	cfg, err := config.Parse([]byte(`princo: v1
nodes:
  a:
    address: a.example.com
    hysteria2: { masquerade: https://www.example.org }
users:
  u: {}
certificates:
  wild:
    domains: ["*.example.com"]
    acme: { dns: cloudflare, env: { CLOUDFLARE_DNS_API_TOKEN: token } }
`))
	require.NoError(t, err)
	f, err := fleet.Build(cfg, secrets.NewStore(map[string]any{"users": map[string]any{"u": "uuid"}}))
	require.NoError(t, err)
	files, err := host.Files(f, "a")
	require.NoError(t, err)
	p, err := host.NewPlan(f, "a", func(string) (string, int) { return "sops:s.yaml#x", 0 })
	require.NoError(t, err)
	b, err := Build(p, files, nil, Earlier{})
	require.NoError(t, err)
	require.Contains(t, string(bundleFile(t, b, CertbotHook).Data), "'wild') units='princo.service'", "lego's deploy hook")
	require.Equal(t, []string{"princo.service", "princo-lego.timer"}, unitNames(b), "no nginx")
	require.False(t, needsSite(p))
}

func TestLegoScript_RestoresMissingCopy(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string, mode os.FileMode) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(data), mode))
	}
	// lego finds renewal not due and runs no hook.
	write("lego", "#!/bin/sh\nexit 0\n", 0o755)
	write("hook", "#!/bin/sh\necho \"$LEGO_HOOK_CERT_NAME $LEGO_HOOK_CERT_PATH $LEGO_HOOK_CERT_KEY_PATH\" >> \"$(dirname \"$0\")/hooked\"\n", 0o755)
	write("state/certificates/wild.crt", "crt", 0o644)
	write("state/certificates/wild.key", "key", 0o600)
	p, _ := certPlan(t)
	script, err := execute("lego.sh", map[string]any{
		"Lego":         filepath.Join(root, "lego"),
		"Dir":          filepath.Join(root, "state"),
		"Hook":         filepath.Join(root, "hook"),
		"CertDir":      filepath.Join(root, "certs"),
		"Certificates": certificates(p, fleet.CertDNS),
		"Env":          dnsEnv,
	})
	require.NoError(t, err)
	write("princo-lego", string(script), 0o755)
	run := func() {
		t.Helper()
		out, err := exec.Command(filepath.Join(root, "princo-lego")).CombinedOutput()
		require.NoError(t, err, string(out))
	}

	run()
	hooked, err := os.ReadFile(filepath.Join(root, "hooked"))
	require.NoError(t, err)
	state := filepath.Join(root, "state", "certificates")
	require.Equal(t, "wild "+state+"/wild.crt "+state+"/wild.key\n", string(hooked))

	write("certs/wild/key.pem", "key", 0o640)
	run()
	again, err := os.ReadFile(filepath.Join(root, "hooked"))
	require.NoError(t, err)
	require.Equal(t, string(hooked), string(again), "a copy in place stays")
}

func TestDeploy_ProbesAgainWithOpenSSL(t *testing.T) {
	p, files := certPlan(t)
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nlego\nprinco 0.2.0\nmonitor\n"}
	d, _ := newDeployer(r, "0.2.0")
	require.NoError(t, d.Deploy(t.Context(), p, files, nil))
	require.Equal(t, []string{"probe", "provision", "probe", "apply", "prune"}, r.steps, "provision brought openssl")

	r = &fakeRemote{t: t, probe: "arch amd64\nengine\nlego\nprinco 0.2.0\nmonitor\nopenssl\nsans wild DNS:example.com,DNS:*.example.com\n"}
	d, _ = newDeployer(r, "0.2.0")
	require.NoError(t, d.Deploy(t.Context(), p, files, nil))
	require.Equal(t, []string{"probe", "provision", "apply", "prune"}, r.steps)
}

// sharedPlan is a node whose subscription site shares certificates with
// its engine: one from files with Naive, and an HTTP-01 one with Hysteria2.
func sharedPlan(t *testing.T) (*host.Plan, map[string][]byte) {
	t.Helper()
	chain, key := certtest.SelfSigned(t, "shop.example.com", "subs.example.com")
	cfg, err := config.Parse([]byte(`princo: v1
nodes:
  a:
    address: a.example.com
    hysteria2: { masquerade: https://www.example.org }
    naive: { domain: shop.example.com }
users:
  u: {}
subscription: { node: a, domains: [subs.example.com, a.example.com, subs.example.org] }
certificates:
  both:
    domains: [shop.example.com, subs.example.com]
    file: {}
`))
	require.NoError(t, err)
	f, err := fleet.Build(cfg, secrets.NewStore(map[string]any{
		"users":        map[string]any{"u": "uuid"},
		"shared":       map[string]any{"hysteria2_obfs": "obfs"},
		"certificates": map[string]any{"both": map[string]any{"fullchain": chain, "key": key}},
	}))
	require.NoError(t, err)
	files, err := host.Files(f, "a")
	require.NoError(t, err)
	p, err := host.NewPlan(f, "a", func(path string) (string, int) { return "sops:s.yaml#" + path, 0 })
	require.NoError(t, err)
	return p, files
}

func TestBuild_SharedCertificates(t *testing.T) {
	p, files := sharedPlan(t)
	b, err := Build(p, files, nil, Earlier{})
	require.NoError(t, err)

	both := path.Join(engine.CertDir, "both")
	require.Equal(t, bundle.Dir{Path: both, Mode: 0o750, Group: engineGroup}, dir(t, b, both))
	require.Equal(t, engineGroup, bundleFile(t, b, both+"/key.pem").Group, "the engine's group reads it, nginx as root")
	require.Equal(t, []string{"princo.service", "princo-loopback.service", "nginx.service"}, unitNames(b))
	require.Contains(t, b.Units[0].Files, both+"/key.pem", "the engine restarts on a new certificate")
	require.Contains(t, b.Units[2].Files, both+"/key.pem", "and nginx reloads")

	hook := string(bundleFile(t, b, CertbotHook).Data)
	require.Contains(t, hook, "'a.example.com') units='princo.service nginx.service' group=princo-engine ;;")
	require.Contains(t, hook, "'subs.example.org') units='nginx.service' group=root ;;")

	conf := string(bundleFile(t, b, SiteConf).Data)
	require.NotContains(t, conf, "The engine's domains", "the site's server answers the challenges of the domains it shares")
	require.Contains(t, conf, "ssl_certificate /var/lib/princo/certs/both/fullchain.pem;")
	require.Contains(t, conf, "ssl_certificate /var/lib/princo/certs/a.example.com/fullchain.pem;")
}

// A certificate copied for other consumers changes hands on the next deploy,
// not on its next renewal.
func TestDeploy_RegroupsCertificates(t *testing.T) {
	p, _ := sharedPlan(t)
	d, _ := newDeployer(&fakeRemote{t: t}, "0.2.0")
	var script string
	d.Remote = remoteFunc(func(s string) { script = s })

	require.NoError(t, d.provision(t.Context(), p))
	require.Contains(t, script, `dir='/var/lib/princo/certs/a.example.com'
if [ -f "$dir/key.pem" ] && ! [ -L "$dir/key.pem" ]; then
	chgrp princo-engine "$dir" "$dir/fullchain.pem" "$dir/key.pem"
fi`)
	require.NotContains(t, script, "subs.example.org", "the engine gets no access to the site's")
	require.NotContains(t, script, "certs/both", "it comes with the bundle")

	require.NoError(t, d.cleanup(t.Context(), p, engines[p.Engine]))
	require.Contains(t, script, `dir='/var/lib/princo/certs/subs.example.org'
if [ -f "$dir/key.pem" ]; then
	chgrp root "$dir" "$dir/fullchain.pem" "$dir/key.pem"
fi`)
	require.NotContains(t, script, "certs/a.example.com")
}

// A unit that fails to reload keeps the others from no new certificate.
func TestCertbotHook_ReloadsEveryUnit(t *testing.T) {
	root := t.TempDir()
	hook, err := execute("certbot-hook", map[string]any{
		"Certificates": []acmeCert{{Name: "wild", Group: "$(id -gn)", Units: "princo.service nginx.service"}},
		"CertDir":      filepath.Join(root, "certs"),
		"Group":        "$(id -gn)",
	})
	require.NoError(t, err)
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	// The engine's reload fails.
	systemctl := "#!/bin/sh\n[ \"$1\" = -q ] && exit 0\necho \"$2\" >> " + shellQuote(filepath.Join(root, "reloaded")) + "\n[ \"$2\" != princo.service ]\n"
	require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"), []byte(systemctl), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "wild.crt"), []byte("crt"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "wild.key"), []byte("key"), 0o600))

	cmd := exec.Command("sh", "-c", string(hook))
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"LEGO_HOOK_CERT_NAME=wild",
		"LEGO_HOOK_CERT_PATH="+filepath.Join(root, "wild.crt"),
		"LEGO_HOOK_CERT_KEY_PATH="+filepath.Join(root, "wild.key"),
	)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "the failure is told: %s", out)
	reloaded, err := os.ReadFile(filepath.Join(root, "reloaded"))
	require.NoError(t, err, string(out))
	require.Equal(t, "princo.service\nnginx.service\n", string(reloaded))
	require.FileExists(t, filepath.Join(root, "certs", "wild", "key.pem"))
}

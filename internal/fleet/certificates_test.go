package fleet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/certtest"
	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/secrets"
)

const certNode = "nodes:\n  a: { address: a.example.com, reality: { server_name: s.example.com, short_id: \"1\", public_key: p } }\n"

func certSecrets(extra map[string]any) map[string]any {
	values := conventionalSecrets()
	values["certificates"] = extra
	return values
}

func TestCertificate_Lookup(t *testing.T) {
	f, err := build(t, certNode+`
certificates:
  wild:
    domains: [example.com, "*.example.com"]
    acme: { dns: cloudflare, env: { CLOUDFLARE_DNS_API_TOKEN: !secret cf } }
  subs:
    domains: [subs.example.com]
    acme: {}
`, func() map[string]any { v := conventionalSecrets(); v["cf"] = "token"; return v }())
	require.NoError(t, err)

	for domain, want := range map[string]string{
		"example.com":      "wild",
		"shop.example.com": "wild",
		"Shop.Example.com": "wild",
		"subs.example.com": "subs",
		"a.b.example.com":  "a.b.example.com",
		"other.org":        "other.org",
	} {
		require.Equal(t, want, f.Certificate(domain).Name, domain)
	}
	wild := f.Certificate("shop.example.com")
	require.Equal(t, CertDNS, wild.Source)
	require.Equal(t, "cloudflare", wild.DNS)
	require.Equal(t, []EnvVar{{"CLOUDFLARE_DNS_API_TOKEN", "token"}}, wild.Env)
	require.Equal(t, CertHTTP, f.Certificate("subs.example.com").Source)
	require.Equal(t, &Certificate{Name: "other.org", Domains: []string{"other.org"}, Source: CertHTTP}, f.Certificate("other.org"), "a domain no entry covers")
	require.Same(t, wild, f.CertificateNamed("wild"))
	require.Equal(t, "other.org", f.CertificateNamed("other.org").Name)
}

func TestCertificate_File(t *testing.T) {
	chain, key := certtest.SelfSigned(t, "static.example.com", "*.cdn.example.com")
	src := certNode + `
certificates:
  own:
    domains: [static.example.com, "*.cdn.example.com"]
    file: {}
`
	f, err := build(t, src, certSecrets(map[string]any{"own": map[string]any{"fullchain": chain, "key": key}}))
	require.NoError(t, err)
	c := f.Certificate("x.cdn.example.com")
	require.Equal(t, CertFile, c.Source)
	require.Equal(t, chain, c.Fullchain)
	require.Equal(t, key, c.Key)

	_, otherKey := certtest.SelfSigned(t, "static.example.com")
	_, err = build(t, src, certSecrets(map[string]any{"own": map[string]any{"fullchain": chain, "key": otherKey}}))
	require.ErrorContains(t, err, "certificates.own.file: tls: private key does not match public key")

	narrow, narrowKey := certtest.SelfSigned(t, "static.example.com", "x.cdn.example.com")
	_, err = build(t, src, certSecrets(map[string]any{"own": map[string]any{"fullchain": narrow, "key": narrowKey}}))
	require.ErrorContains(t, err, "certificates.own.file.fullchain: doesn't cover *.cdn.example.com; it has static.example.com, x.cdn.example.com")

	_, err = build(t, src, certSecrets(map[string]any{"own": map[string]any{"fullchain": "junk", "key": key}}))
	require.ErrorContains(t, err, "certificates.own.file: tls: failed to find any PEM data in certificate input")

	cfg, err := config.Parse([]byte("princo: v1\n" + src))
	require.NoError(t, err)
	f, err = Build(cfg, secrets.AllPlaceholders{})
	require.NoError(t, err, "placeholders aren't checked")
	require.Equal(t, secrets.Placeholder("certificates/own/fullchain"), f.Certificate("static.example.com").Fullchain)
}

func TestCertificate_Invalid(t *testing.T) {
	for src, want := range map[string]string{
		"Bad: { domains: [a.example.com], acme: {} }": `certificates.Bad: name "Bad"`,
		"c: { acme: {} }":                                                                        "certificates.c.domains: required",
		"c: { domains: [a.example.com] }":                                                        "certificates.c: set one of acme and file",
		"c: { domains: [a.example.com], acme: {}, file: {} }":                                    "certificates.c: set one of acme and file",
		`c: { domains: ["*.example.com"], acme: {} }`:                                            "certificates.c.acme: a wildcard needs dns: HTTP-01 can't issue one",
		`c: { domains: ["*.com"], acme: { dns: x } }`:                                            `certificates.c.domains: "*.com" isn't a domain`,
		`c: { domains: ["a.*.example.com"], acme: { dns: x } }`:                                  `certificates.c.domains: "a.*.example.com" isn't a domain`,
		"c: { domains: [a.example.com], acme: { env: { A: b } } }":                               "certificates.c.acme.env: only for acme.dns",
		"c: { domains: [a.example.com], acme: { dns: Cloud Flare } }":                            `certificates.c.acme.dns: "Cloud Flare" isn't a lego DNS provider's name`,
		"c: { domains: [a.example.com], acme: { dns: x, env: { 1A: b } } }":                      "certificates.c.acme.env.1A: not an environment variable's name",
		"c: { domains: [a.example.com], acme: { dns: x, env: { A: \"b\\nC=d\" } } }":             "certificates.c.acme.env.A: takes one line",
		"c: { domains: [a.example.com], acme: { dns: x, env: { A: \"it's\" } } }":                "certificates.c.acme.env.A: takes one line, without '",
		"c: { domains: [a.example.com], acme: {} }\n  d: { domains: [A.example.com], acme: {} }": "certificates.d.domains: a.example.com is certificates.c's too",
	} {
		_, err := build(t, certNode+"certificates:\n  "+src+"\n", conventionalSecrets())
		require.ErrorContains(t, err, want, src)
	}
}

func TestSecrets_Certificates(t *testing.T) {
	cfg, err := config.Parse([]byte("princo: v1\n" + certNode + `
certificates:
  own: { domains: [a.example.com], file: { key: !secret keys/own } }
  wild: { domains: ["*.example.com"], acme: { dns: cloudflare, env: { TOKEN: !secret cf } } }
`))
	require.NoError(t, err)
	var got []SecretUse
	for _, u := range Secrets(cfg) {
		if u.Field[0] == 'c' {
			got = append(got, u)
		}
	}
	require.Equal(t, []SecretUse{
		{Path: "certificates/own/fullchain", Field: "certificates.own.file.fullchain", Kind: SecretExternal},
		{Path: "keys/own", Field: "certificates.own.file.key", Kind: SecretExternal},
		{Path: "cf", Field: "certificates.wild.acme.env.TOKEN", Kind: SecretExternal},
	}, got)
}

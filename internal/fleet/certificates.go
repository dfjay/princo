package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"regexp"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/secrets"
)

// Where a certificate comes from: each node issues CertHTTP and CertDNS
// over ACME, CertFile comes from secrets.
const (
	CertHTTP = "http"
	CertDNS  = "dns"
	CertFile = "file"
)

// Certificate is one nodes serve, in engine.CertDir/<Name>.
type Certificate struct {
	// Name is its entry's in princo.yaml, or for a domain no entry covers,
	// the domain.
	Name    string
	Domains []string
	Source  string
	// DNS is CertDNS's lego provider, Env its credentials.
	DNS string
	Env []EnvVar
	// Fullchain and Key are CertFile's PEM.
	Fullchain, Key string
}

// EnvVar is a NAME=value pair.
type EnvVar struct {
	Name, Value string
}

// Certificate returns the certificate for domain: the entry naming it, else
// one whose wildcard covers it, else an HTTP-01 one of its own.
func (f *Fleet) Certificate(domain string) *Certificate {
	d := strings.ToLower(domain)
	if c := f.certFor(func(pattern string) bool { return pattern == d }); c != nil {
		return c
	}
	if c := f.certFor(func(pattern string) bool { return coversWildcard(pattern, d) }); c != nil {
		return c
	}
	return &Certificate{Name: domain, Domains: []string{domain}, Source: CertHTTP}
}

// CertificateNamed returns the certificate that Certificate names name.
func (f *Fleet) CertificateNamed(name string) *Certificate {
	for _, c := range f.Certificates {
		if c.Name == name {
			return c
		}
	}
	return f.Certificate(name)
}

func (f *Fleet) certFor(match func(pattern string) bool) *Certificate {
	for _, c := range f.Certificates {
		if slices.ContainsFunc(c.Domains, match) {
			return c
		}
	}
	return nil
}

// coversWildcard reports whether pattern, *.<parent>, covers domain.
func coversWildcard(pattern, domain string) bool {
	parent, ok := strings.CutPrefix(pattern, "*.")
	if !ok {
		return false
	}
	_, rest, ok := strings.Cut(domain, ".")
	return ok && rest == parent
}

// lego names its DNS providers like route53 or httpreq.
var dnsProviderRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func secretCertificate(name, field string) string { return "certificates/" + name + "/" + field }

func (b *builder) certificates() {
	claimed := map[string]string{}
	for name, c := range b.cfg.Certificates.All() {
		where := "certificates." + name
		b.checkName(where, name)
		cert := &Certificate{Name: name}
		if len(c.Domains) == 0 {
			b.errorf("%s.domains: required", where)
		}
		wildcard := false
		for _, d := range c.Domains {
			d = strings.ToLower(d)
			parent, isWildcard := strings.CutPrefix(d, "*.")
			wildcard = wildcard || isWildcard
			if !hostnameRe.MatchString(parent) || isWildcard && !strings.Contains(parent, ".") || len(d) > 253 {
				b.errorf("%s.domains: %q isn't a domain or a wildcard like *.example.com", where, d)
				continue
			}
			if other, ok := claimed[d]; ok {
				b.errorf("%s.domains: %s is certificates.%s's too", where, d, other)
				continue
			}
			claimed[d] = name
			cert.Domains = append(cert.Domains, d)
		}

		switch {
		case (c.ACME == nil) == (c.File == nil):
			b.errorf("%s: set one of acme and file", where)
		case c.ACME != nil:
			cert.Source = CertHTTP
			if c.ACME.DNS != "" {
				cert.Source, cert.DNS = CertDNS, c.ACME.DNS
				if !dnsProviderRe.MatchString(c.ACME.DNS) {
					b.errorf("%s.acme.dns: %q isn't a lego DNS provider's name, like cloudflare", where, c.ACME.DNS)
				}
			} else if c.ACME.Env.Len() > 0 {
				b.errorf("%s.acme.env: only for acme.dns, the provider's credentials", where)
			}
			if wildcard && cert.Source == CertHTTP {
				b.errorf("%s.acme: a wildcard needs dns: HTTP-01 can't issue one", where)
			}
			for key, v := range c.ACME.Env.All() {
				at := where + ".acme.env." + key
				if !envNameRe.MatchString(key) {
					b.errorf("%s: not an environment variable's name", at)
				}
				value := b.secret(at, &v, "", SecretExternal)
				if strings.ContainsAny(value, "\n\r'") {
					b.errorf("%s: takes one line, without '", at)
				}
				cert.Env = append(cert.Env, EnvVar{Name: key, Value: value})
			}
		default:
			cert.Source = CertFile
			cert.Fullchain = b.secret(where+".file.fullchain", c.File.Fullchain, secretCertificate(name, "fullchain"), SecretExternal)
			cert.Key = b.secret(where+".file.key", c.File.Key, secretCertificate(name, "key"), SecretExternal)
			b.checkCertFile(where+".file", cert)
		}
		b.f.Certificates = append(b.f.Certificates, cert)
	}
}

// checkCertFile checks a certificate from secrets against its key and
// domains. Not its expiry: rendering mustn't stop the engine when it lapses.
func (b *builder) checkCertFile(where string, c *Certificate) {
	if len(secrets.Placeholders([]byte(c.Fullchain+c.Key))) > 0 {
		return
	}
	pair, err := tls.X509KeyPair([]byte(c.Fullchain), []byte(c.Key))
	if err != nil {
		b.errorf("%s: %v", where, err)
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		b.errorf("%s.fullchain: %v", where, err)
		return
	}
	for _, d := range c.Domains {
		ok := leaf.VerifyHostname(d) == nil
		if strings.HasPrefix(d, "*.") {
			ok = slices.ContainsFunc(leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, d) })
		}
		if !ok {
			b.errorf("%s.fullchain: doesn't cover %s; it has %s", where, d, strings.Join(leaf.DNSNames, ", "))
		}
	}
}

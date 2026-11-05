// Package host describes one node's machine: the files princo renders for
// it, and the plan of what a deploy sets up around them (ports, the SNI
// multiplexer, certificates, rule sets, secrets).
package host

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/engine"
	_ "github.com/dfjay/princo/internal/engine/singbox"
	_ "github.com/dfjay/princo/internal/engine/xray"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/secrets"
	"github.com/dfjay/princo/internal/subscription"
)

// SiteAddr is where the host's web server serves HTTPS sites, the
// subscription site among them, behind the multiplexer.
const SiteAddr = "127.0.0.1:8443"

// Paths of the rendered files, relative to the output directory.
const (
	// SiteDir is the root of the subscription site.
	SiteDir = "subscription"
	// TokensFile lists "<user> <token>" per line; it sits outside the site
	// so the web server never serves it.
	TokensFile = "tokens.txt"
	// CertsDir holds the certificates' files from secrets: <name>/{fullchain,
	// key}.pem, or <name>/dns.env with the DNS provider's credentials.
	CertsDir = "certificates"
)

// ConfigFile is the server config's path for an engine, e.g. sing-box.json.
func ConfigFile(engineName string) string { return engineName + ".json" }

// Files renders everything the node runs from, keyed by path relative to
// the output directory: the server config and, on the node serving it, the
// subscription site and its tokens.
func Files(f *fleet.Fleet, node string) (map[string][]byte, error) {
	n, ok := f.Node(node)
	if !ok {
		return nil, fmt.Errorf("no node named %q", node)
	}
	e, err := engine.Lookup(n.Engine)
	if err != nil {
		return nil, err
	}
	cfg, err := e.RenderServer(f, node)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{ConfigFile(n.Engine): append(cfg, '\n')}
	engineCerts, siteCert := certificates(f, n, cfg)
	if siteCert != "" {
		engineCerts = append(engineCerts, siteCert)
	}
	for _, name := range engineCerts {
		addCertFiles(files, f.CertificateNamed(name))
	}
	if !n.ServesSubscription {
		return files, nil
	}

	client, err := engine.Lookup(engine.ClientEngine)
	if err != nil {
		return nil, err
	}
	site, err := subscription.Site(f, client)
	if err != nil {
		return nil, err
	}
	for p, data := range site {
		files[path.Join(SiteDir, p)] = data
	}
	var tokens strings.Builder
	for _, u := range f.Users {
		fmt.Fprintf(&tokens, "%s %s\n", u.Name, subscription.Token(u))
	}
	files[TokensFile] = []byte(tokens.String())
	return files, nil
}

// Plan is what a deploy needs to know about a node beyond its files. It
// holds no secret values, so it can be computed without them.
type Plan struct {
	Node   string `json:"node"`
	Engine string `json:"engine"`
	// EngineMinVersion is the oldest engine release the config works on.
	EngineMinVersion string `json:"engine_min_version"`
	// Config is the server config's path among the rendered files.
	Config   string `json:"config"`
	TCPPorts []int  `json:"tcp_ports"`
	UDPPorts []int  `json:"udp_ports"`
	// Mux is the SNI multiplexer on TCP 443; nil when the engine has 443 alone.
	Mux *Mux `json:"mux,omitzero"`
	// Certificates are the ones the node needs, in
	// engine.CertDir/<name>/{fullchain,key}.pem.
	Certificates []Certificate `json:"certificates"`
	ACMEEmail    string        `json:"acme_email,omitempty"`
	// RuleSets are the files the server config loads from engine.RuleSetDir,
	// in the engine's format (e.g. geoip-ru.srs for sing-box).
	RuleSets []string `json:"rule_sets"`
	// SiteRuleSets are the client profiles' other rule sets in
	// engine.RuleSetDir, which the subscription site serves.
	SiteRuleSets []string `json:"site_rule_sets"`
	// RuleData is what the rule sets are built from.
	RuleData fleet.RuleData `json:"rule_data"`
	// Subscription is the site the node serves; nil on other nodes.
	Subscription *Site `json:"subscription,omitzero"`
	// Secrets are the ones rendering this node's files reads.
	Secrets []Secret `json:"secrets"`
}

// Mux routes TLS connections on TCP 443 by SNI.
type Mux struct {
	Port   int     `json:"port"`
	Routes []Route `json:"routes"`
	// Default takes connections no route matches; nil when nothing does.
	Default *Route `json:"default,omitzero"`
	// Loopback is nil when no route goes to the engine.
	Loopback *Loopback `json:"loopback,omitzero"`
}

// Route sends a connection to Target or to the engine at EnginePort.
type Route struct {
	// SNI is empty on the default route.
	SNI    string `json:"sni,omitempty"`
	Target string `json:"target,omitempty"`
	// EnginePort is listened on at 127.0.0.1 and ::1. The multiplexer
	// connects to the client's family from the client's address, so the
	// engine sees who connects.
	EnginePort int `json:"engine_port,omitempty"`
}

// Loopback keeps the engine's replies to the clients' addresses local: a
// rule per port sends them to Table, which delivers everything locally,
// back to the multiplexer.
type Loopback struct {
	// Table is the routing table and the rules' preference.
	Table int   `json:"table"`
	Ports []int `json:"ports"`
}

// LoopbackTable precedes the rules of Tailscale (5210 and up) and of the
// main table (32766).
const LoopbackTable = 4430

// Certificate is one the node serves; see fleet.Certificate.
type Certificate struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Source  string   `json:"source"`
	DNS     string   `json:"dns,omitempty"`
	// Site tells that nginx serves it, for the subscription site, rather
	// than the engine.
	Site bool `json:"site,omitempty"`
}

type Site struct {
	Domain string `json:"domain"`
	// Certificate names the site's in Plan.Certificates.
	Certificate string `json:"certificate"`
	// Root is the site's directory among the rendered files.
	Root string `json:"root"`
	// Listen is where the web server serves it over HTTPS.
	Listen string `json:"listen"`
}

// Secret is one secret the node needs: its logical path, the file it is
// read from in a secrets dir (secrets.Dir), and where it is stored.
type Secret struct {
	Path   string `json:"path"`
	File   string `json:"file"`
	Source Source `json:"source"`
}

// Source is where a secret is stored: Key in an encrypted File of Type
// sops or age. File is relative to the directory of config file Config,
// an index into the --config files.
type Source struct {
	Type   string `json:"type"`
	File   string `json:"file"`
	Key    string `json:"key"`
	Config int    `json:"config"`
}

var certRe = regexp.MustCompile(regexp.QuoteMeta(engine.CertDir) + `/([^/"]+)/`)

// siteRuleSetRe finds the rule sets client profiles get from the site.
var siteRuleSetRe = regexp.MustCompile(`https://[^/"]+` + regexp.QuoteMeta(engine.RuleSetSitePath) + `([^/"]+\.srs)"`)

// NewPlan plans node. f must be built with secrets.AllPlaceholders: the
// plan reads the secrets, rule sets and certificates off the rendered
// files, so it always matches what render writes. locate tells where a
// secret path is stored and which config file that location is relative to.
func NewPlan(f *fleet.Fleet, node string, locate func(path string) (string, int)) (*Plan, error) {
	files, err := Files(f, node)
	if err != nil {
		return nil, err
	}
	n, _ := f.Node(node)
	e, err := engine.Lookup(n.Engine)
	if err != nil {
		return nil, err
	}
	p := &Plan{
		Node:             node,
		Engine:           n.Engine,
		EngineMinVersion: e.MinVersion(),
		Config:           ConfigFile(n.Engine),
		TCPPorts:         []int{},
		UDPPorts:         []int{},
		Certificates:     []Certificate{},
		ACMEEmail:        n.ACMEEmail,
		RuleSets:         e.RuleSets(files[ConfigFile(n.Engine)]),
		SiteRuleSets:     []string{},
		RuleData:         f.RuleData,
		Secrets:          []Secret{},
	}
	if n.Reality != nil || n.Mux() {
		p.TCPPorts = append(p.TCPPorts, 443)
	}
	if n.Hysteria2 != nil {
		p.UDPPorts = append(p.UDPPorts, 443)
	}
	if n.Mux() {
		p.Mux = newMux(f, n)
	}
	engineCerts, siteCert := certificates(f, n, files[ConfigFile(n.Engine)])
	for _, name := range engineCerts {
		if name == siteCert {
			return nil, fmt.Errorf("subscription.domain: node %s's engine has certificate %s too, which it can't share with the web server; give the site a certificate of its own", node, name)
		}
		p.Certificates = append(p.Certificates, planCertificate(f.CertificateNamed(name), false))
	}
	if n.ServesSubscription {
		p.Subscription = &Site{Domain: f.Subscription.Domain, Certificate: siteCert, Root: SiteDir, Listen: SiteAddr}
		p.Certificates = append(p.Certificates, planCertificate(f.CertificateNamed(siteCert), true))
	}
	slices.SortFunc(p.Certificates, func(a, b Certificate) int { return strings.Compare(a.Name, b.Name) })

	var secretPaths []string
	for _, name := range slices.Sorted(maps.Keys(files)) {
		data := files[name]
		secretPaths = append(secretPaths, secrets.Placeholders(data)...)
		if strings.HasPrefix(name, SiteDir+"/") {
			for _, m := range siteRuleSetRe.FindAllSubmatch(data, -1) {
				if name := string(m[1]); !slices.Contains(p.RuleSets, name) {
					p.SiteRuleSets = append(p.SiteRuleSets, name)
				}
			}
		}
	}
	p.RuleSets = sortedUnique(p.RuleSets)
	p.SiteRuleSets = sortedUnique(p.SiteRuleSets)
	for _, s := range sortedUnique(secretPaths) {
		location, config := locate(s)
		kind, file, key, err := secrets.ParseLocation(location)
		if err != nil {
			return nil, err
		}
		p.Secrets = append(p.Secrets, Secret{Path: s, File: s, Source: Source{Type: kind, File: file, Key: key, Config: config}})
	}
	return p, nil
}

// certificates names the certificates n's engine config cfg reads, and
// the subscription site's if n serves it.
func certificates(f *fleet.Fleet, n *fleet.Node, cfg []byte) (engineCerts []string, site string) {
	for _, m := range certRe.FindAllSubmatch(cfg, -1) {
		engineCerts = append(engineCerts, string(m[1]))
	}
	if n.ServesSubscription {
		site = f.Certificate(f.Subscription.Domain).Name
	}
	return sortedUnique(engineCerts), site
}

// addCertFiles adds what certificate c needs from secrets to files.
func addCertFiles(files map[string][]byte, c *fleet.Certificate) {
	dir := path.Join(CertsDir, c.Name)
	switch c.Source {
	case fleet.CertFile:
		files[path.Join(dir, "fullchain.pem")] = []byte(c.Fullchain)
		files[path.Join(dir, "key.pem")] = []byte(c.Key)
	case fleet.CertDNS:
		var env strings.Builder
		for _, v := range c.Env {
			// Single quotes keep it literal for systemd and lego alike.
			fmt.Fprintf(&env, "%s='%s'\n", v.Name, v.Value)
		}
		files[path.Join(dir, "dns.env")] = []byte(env.String())
	}
}

func planCertificate(c *fleet.Certificate, site bool) Certificate {
	return Certificate{Name: c.Name, Domains: c.Domains, Source: c.Source, DNS: c.DNS, Site: site}
}

func newMux(f *fleet.Fleet, n *fleet.Node) *Mux {
	m := &Mux{Port: 443, Routes: []Route{}}
	var enginePorts []int
	for _, pt := range n.Passthrough {
		m.Routes = append(m.Routes, Route{SNI: pt.Host, Target: pt.Target})
	}
	if n.ServesSubscription {
		m.Routes = append(m.Routes, Route{SNI: f.Subscription.Domain, Target: SiteAddr})
	}
	if n.Naive != nil {
		m.Routes = append(m.Routes, Route{SNI: n.Naive.Domain, EnginePort: engine.MuxNaivePort})
		enginePorts = append(enginePorts, engine.MuxNaivePort)
	}
	if n.Reality != nil {
		m.Default = &Route{EnginePort: engine.MuxRealityPort}
		enginePorts = append(enginePorts, engine.MuxRealityPort)
	}
	if len(enginePorts) > 0 {
		slices.Sort(enginePorts)
		m.Loopback = &Loopback{Table: LoopbackTable, Ports: enginePorts}
	}
	return m
}

// AllRuleSets are the files of RuleSets and SiteRuleSets.
func (p *Plan) AllRuleSets() []string {
	return sortedUnique(slices.Concat(p.RuleSets, p.SiteRuleSets))
}

func sortedUnique(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

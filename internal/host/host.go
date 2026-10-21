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
	"strconv"
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
	if !n.ServesSubscription {
		return files, nil
	}

	client, err := engine.Lookup(engine.ClientEngine)
	if err != nil {
		return nil, err
	}
	site, err := subscription.Site(f, func(user string) ([]byte, error) { return client.RenderClient(f, user) })
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
	// Certificates are the domains whose certificates the node needs, in
	// engine.CertDir/<domain>/{fullchain,key}.pem.
	Certificates []string `json:"certificates"`
	ACMEEmail    string   `json:"acme_email,omitempty"`
	// RuleSets are the files the server config loads from engine.RuleSetDir,
	// in the engine's format (e.g. geoip-ru.srs for sing-box).
	RuleSets []string `json:"rule_sets"`
	// Subscription is the site the node serves; nil on other nodes.
	Subscription *Site `json:"subscription,omitzero"`
	// Secrets are the ones rendering this node's files reads.
	Secrets []Secret `json:"secrets"`
}

// Mux routes TLS connections on TCP 443 by SNI.
type Mux struct {
	Port   int     `json:"port"`
	Routes []Route `json:"routes"`
	// Default takes connections no route matches; empty when nothing does.
	Default string `json:"default,omitempty"`
}

type Route struct {
	SNI    string `json:"sni"`
	Target string `json:"target"`
}

type Site struct {
	Domain string `json:"domain"`
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

// Source is where a secret is stored: Key in an encrypted File (relative to
// princo.yaml's directory) of Type sops or age.
type Source struct {
	Type string `json:"type"`
	File string `json:"file"`
	Key  string `json:"key"`
}

var certRe = regexp.MustCompile(regexp.QuoteMeta(engine.CertDir) + `/([^/"]+)/`)

// NewPlan plans node. f must be built with secrets.AllPlaceholders: the
// plan reads the secrets, rule sets and certificates off the rendered
// files, so it always matches what render writes. locate tells where a
// secret path is stored.
func NewPlan(f *fleet.Fleet, node string, locate func(path string) string) (*Plan, error) {
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
		Certificates:     []string{},
		ACMEEmail:        n.ACMEEmail,
		RuleSets:         e.RuleSets(files[ConfigFile(n.Engine)]),
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
	if n.ServesSubscription {
		p.Subscription = &Site{Domain: f.Subscription.Domain, Root: SiteDir, Listen: SiteAddr}
		p.Certificates = append(p.Certificates, f.Subscription.Domain)
	}

	var secretPaths []string
	for _, name := range slices.Sorted(maps.Keys(files)) {
		data := files[name]
		secretPaths = append(secretPaths, secrets.Placeholders(data)...)
		for _, m := range certRe.FindAllSubmatch(data, -1) {
			p.Certificates = append(p.Certificates, string(m[1]))
		}
	}
	p.RuleSets = sortedUnique(p.RuleSets)
	p.Certificates = sortedUnique(p.Certificates)
	for _, s := range sortedUnique(secretPaths) {
		kind, file, key, err := secrets.ParseLocation(locate(s))
		if err != nil {
			return nil, err
		}
		p.Secrets = append(p.Secrets, Secret{Path: s, File: secrets.FileName(s), Source: Source{Type: kind, File: file, Key: key}})
	}
	return p, nil
}

func newMux(f *fleet.Fleet, n *fleet.Node) *Mux {
	local := func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }
	m := &Mux{Port: 443, Routes: []Route{}}
	for _, pt := range n.Passthrough {
		m.Routes = append(m.Routes, Route{SNI: pt.Host, Target: pt.Target})
	}
	if n.ServesSubscription {
		m.Routes = append(m.Routes, Route{SNI: f.Subscription.Domain, Target: SiteAddr})
	}
	if n.Naive != nil {
		m.Routes = append(m.Routes, Route{SNI: n.Naive.Domain, Target: local(engine.MuxNaivePort)})
	}
	if n.Reality != nil {
		m.Default = local(engine.MuxRealityPort)
	}
	return m
}

func sortedUnique(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

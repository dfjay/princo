// Package deploy runs a node on a Debian or Ubuntu host over SSH: Build
// makes the node's bundle, and Deployer prepares the host and applies it.
package deploy

import (
	"bytes"
	"embed"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"text/template"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
)

// Paths on the host.
const (
	FilesDir = "/var/lib/princo/files"
	// ACMEDir is certbot's webroot for HTTP-01 challenges.
	ACMEDir  = "/var/lib/princo/acme"
	UnitFile = "/etc/systemd/system/princo.service"
	// Debian's nginx.conf includes modules-enabled at the top level, where
	// a stream block must be.
	StreamConf  = "/etc/nginx/modules-enabled/99-princo-stream.conf"
	SiteConf    = "/etc/nginx/sites-enabled/princo.conf"
	CertbotHook = "/etc/letsencrypt/renewal-hooks/deploy/princo"
)

// nginx passes through stateDir to the site and the ACME webroot.
var stateDir = bundle.Dir{Path: bundle.StateDir, Mode: 0o755}

// webGroup is the group Debian's nginx runs as.
const webGroup = "www-data"

// engineGroup may read the engine's config and certificates.
const engineGroup = "princo-engine"

//go:embed templates
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{"q": shellQuote}).ParseFS(templateFS, "templates/*"))

// Earlier tells which of nginx's files an earlier deploy left on the host.
// Build keeps them, emptied if need be, so nginx lets go of what they
// served.
type Earlier struct {
	Stream, Site bool
}

// Build is the bundle of node p.Node from its rendered files (host.Files)
// and rule sets. The host must have the plan's certificates (Bootstrap).
func Build(p *host.Plan, files, ruleSets map[string][]byte, earlier Earlier) (*bundle.Bundle, error) {
	e, ok := engines[p.Engine]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s yet", p.Engine)
	}
	b := &bundle.Bundle{Format: bundle.Format, Node: p.Node, Dirs: []bundle.Dir{stateDir}}

	filesDir := bundle.Dir{Path: FilesDir, Mode: 0o750, Group: engineGroup}
	if p.Subscription != nil {
		filesDir.Mode = 0o751
	}
	b.Dirs = append(b.Dirs, filesDir)
	if p.Subscription != nil {
		b.Dirs = append(b.Dirs, bundle.Dir{Path: path.Join(FilesDir, p.Subscription.Root), Mode: 0o750, Group: webGroup})
	}
	config := path.Join(FilesDir, p.Config)
	engineFiles, siteFiles := addCertFiles(b, p, files)
	engineFiles = append([]string{UnitFile}, engineFiles...)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if certFile(name) {
			continue
		}
		f := bundle.File{Path: path.Join(FilesDir, name), Mode: 0o600, Data: files[name]}
		if p.Subscription != nil && strings.HasPrefix(name, p.Subscription.Root+"/") {
			f.Mode, f.Group = 0o640, webGroup
		}
		if f.Path == config {
			f.Mode, f.Group = 0o640, engineGroup
			engineFiles = append(engineFiles, f.Path)
		}
		b.Files = append(b.Files, f)
	}
	for _, name := range p.AllRuleSets() {
		data, ok := ruleSets[name]
		if !ok {
			return nil, fmt.Errorf("rule set %s is missing", name)
		}
		f := path.Join(engine.RuleSetDir, name)
		b.Files = append(b.Files, bundle.File{Path: f, Mode: 0o644, Data: data})
		// The site's alone don't restart the engine.
		if slices.Contains(p.RuleSets, name) {
			engineFiles = append(engineFiles, f)
		}
	}

	bin := e.bin()
	unit, err := execute("princo.service", map[string]any{
		"Node":        p.Node,
		"Engine":      p.Engine,
		"Environment": e.environment,
		"ExecStart":   strings.Join(e.command(bin, config, "/var/lib/princo-"+p.Engine), " "),
		"Reloads":     e.reloads,
		"ConfigError": e.configError,
		"StateDir":    "princo-" + p.Engine,
		"Group":       engineGroup,
	})
	if err != nil {
		return nil, err
	}
	b.Files = append(b.Files, bundle.File{Path: UnitFile, Mode: 0o644, Data: unit})
	units := []bundle.Unit{{Name: "princo.service", Files: engineFiles, Check: e.check(bin, config)}}

	nginxFiles := siteFiles
	if p.Mux != nil || earlier.Stream {
		conf, err := execute("stream.conf", p)
		if err != nil {
			return nil, err
		}
		b.Files = append(b.Files, bundle.File{Path: StreamConf, Mode: 0o644, Data: conf})
		nginxFiles = append(nginxFiles, StreamConf)
	}
	if needsSite(p) || earlier.Site {
		if err := addSite(b, p, true); err != nil {
			return nil, err
		}
		nginxFiles = append(nginxFiles, SiteConf)
	}
	if err := addHook(b, p); err != nil {
		return nil, err
	}
	if len(nginxFiles) > 0 {
		units = append(units, nginxUnit(nginxFiles))
	}
	if len(certificates(p, fleet.CertDNS)) > 0 {
		if err := addLego(b, p); err != nil {
			return nil, err
		}
		units = append(units, bundle.Unit{Name: "princo-lego.timer", Files: []string{LegoService, LegoTimer}})
	}
	// Whichever leaves TCP 443 goes first. Losing the multiplexer, nginx
	// restarts on the emptied StreamConf: reloaded, its old workers would
	// hold the port a while.
	if p.Mux == nil && earlier.Stream {
		units[1].Reload = false
		slices.Reverse(units)
	}
	b.Units = units
	return b, nil
}

// Bootstrap is the partial bundle that readies the host to issue the
// missing certificates, leaving the rest of the node: nginx answers the
// ACME challenges, lego has its script and credentials.
func Bootstrap(p *host.Plan, files map[string][]byte, missing []string) (*bundle.Bundle, error) {
	b := &bundle.Bundle{Format: bundle.Format, Node: p.Node, Partial: true, Dirs: []bundle.Dir{stateDir}}
	_, siteFiles := addCertFiles(b, p, files)
	for _, c := range certificates(p, fleet.CertDNS) {
		f := dnsEnv(c.Name)
		b.Files = append(b.Files, bundle.File{Path: path.Join(FilesDir, f), Mode: 0o600, Data: files[f]})
	}
	if needsSite(p) {
		siteTLS := p.Subscription != nil && !slices.Contains(missing, p.Subscription.Certificate)
		if err := addSite(b, p, siteTLS); err != nil {
			return nil, err
		}
		b.Units = append(b.Units, nginxUnit(append(siteFiles, SiteConf)))
	}
	if err := addHook(b, p); err != nil {
		return nil, err
	}
	if len(certificates(p, fleet.CertDNS)) > 0 {
		if err := addLego(b, p); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// needsSite tells whether nginx serves the subscription site or HTTP-01
// challenges.
func needsSite(p *host.Plan) bool {
	return p.Subscription != nil || len(certificates(p, fleet.CertHTTP)) > 0
}

// certificates are the node's certificates from sources.
func certificates(p *host.Plan, sources ...string) []host.Certificate {
	return slices.DeleteFunc(slices.Clone(p.Certificates), func(c host.Certificate) bool { return !slices.Contains(sources, c.Source) })
}

// certificate is the node's certificate name.
func certificate(p *host.Plan, name string) (host.Certificate, bool) {
	i := slices.IndexFunc(p.Certificates, func(c host.Certificate) bool { return c.Name == name })
	if i < 0 {
		return host.Certificate{}, false
	}
	return p.Certificates[i], true
}

// certFile tells whether a rendered file is a certificate's PEM, which goes
// to engine.CertDir.
func certFile(name string) bool {
	return strings.HasPrefix(name, host.CertsDir+"/") && strings.HasSuffix(name, ".pem")
}

// addCertFiles adds the certificates from secrets to b, and returns the
// files the engine and nginx read.
func addCertFiles(b *bundle.Bundle, p *host.Plan, files map[string][]byte) (engineFiles, siteFiles []string) {
	certs := certificates(p, fleet.CertFile)
	if len(certs) > 0 {
		b.Dirs = append(b.Dirs, bundle.Dir{Path: engine.CertDir, Mode: 0o750, Group: engineGroup})
	}
	for _, c := range certs {
		group := engineGroup
		if c.Site {
			group = ""
		}
		dir := path.Join(engine.CertDir, c.Name)
		b.Dirs = append(b.Dirs, bundle.Dir{Path: dir, Mode: 0o750, Group: group})
		for _, name := range []string{"fullchain.pem", "key.pem"} {
			f := path.Join(dir, name)
			b.Files = append(b.Files, bundle.File{Path: f, Mode: 0o640, Group: group, Data: files[path.Join(host.CertsDir, c.Name, name)]})
			if c.Site {
				siteFiles = append(siteFiles, f)
			} else {
				engineFiles = append(engineFiles, f)
			}
		}
	}
	return engineFiles, siteFiles
}

// addSite adds nginx's sites and the ACME webroot; siteTLS serves the
// subscription site, which needs its certificate.
func addSite(b *bundle.Bundle, p *host.Plan, siteTLS bool) error {
	data := map[string]any{
		"Node":          p.Node,
		"EngineDomains": engineDomains(p),
		"Site":          p.Subscription,
		"SiteTLS":       siteTLS,
		"SiteACME":      slices.ContainsFunc(certificates(p, fleet.CertHTTP), func(c host.Certificate) bool { return c.Site }),
		"ACMEDir":       ACMEDir,
		"CertDir":       engine.CertDir,
		"RuleSetDir":    engine.RuleSetDir,
		"RuleSetPath":   engine.RuleSetSitePath,
	}
	if p.Subscription != nil {
		data["Root"] = path.Join(FilesDir, p.Subscription.Root)
	}
	conf, err := execute("site.conf", data)
	if err != nil {
		return err
	}
	b.Dirs = append(b.Dirs, bundle.Dir{Path: ACMEDir, Mode: 0o755})
	b.Files = append(b.Files, bundle.File{Path: SiteConf, Mode: 0o644, Data: conf})
	return nil
}

// addHook adds the hook that copies ACME certificates, if there are any.
func addHook(b *bundle.Bundle, p *host.Plan) error {
	if len(certificates(p, fleet.CertHTTP, fleet.CertDNS)) == 0 {
		return nil
	}
	hook, err := certbotHook(p)
	if err != nil {
		return err
	}
	b.Files = append(b.Files, bundle.File{Path: CertbotHook, Mode: 0o755, Data: hook})
	return nil
}

// certbotHook copies the certificates certbot and lego issue.
func certbotHook(p *host.Plan) ([]byte, error) {
	return execute("certbot-hook", map[string]any{
		"Certificates": certificates(p, fleet.CertHTTP, fleet.CertDNS),
		"CertDir":      engine.CertDir,
		"Group":        engineGroup,
	})
}

// engineDomains are the domains of the engine's HTTP-01 certificates.
func engineDomains(p *host.Plan) []string {
	var out []string
	for _, c := range certificates(p, fleet.CertHTTP) {
		if !c.Site {
			out = append(out, c.Domains...)
		}
	}
	return out
}

func nginxUnit(files []string) bundle.Unit {
	return bundle.Unit{Name: "nginx.service", Files: files, Reload: true, Check: []string{"nginx", "-t", "-q"}}
}

func execute(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

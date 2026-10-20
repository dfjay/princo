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

//go:embed templates
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{"q": shellQuote}).ParseFS(templateFS, "templates/*"))

// Build is the bundle of node p.Node from its rendered files (host.Files)
// and rule sets. The host must have the plan's certificates (Bootstrap).
// hostStream tells that the host has a StreamConf from an earlier deploy.
func Build(p *host.Plan, files, ruleSets map[string][]byte, hostStream bool) (*bundle.Bundle, error) {
	e, ok := engines[p.Engine]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s yet", p.Engine)
	}
	b := &bundle.Bundle{Format: bundle.Format, Node: p.Node, Dirs: []bundle.Dir{stateDir}}

	filesDir := bundle.Dir{Path: FilesDir, Mode: 0o700}
	if p.Subscription != nil {
		filesDir.Mode = 0o751
	}
	b.Dirs = append(b.Dirs, filesDir)
	if p.Subscription != nil {
		b.Dirs = append(b.Dirs, bundle.Dir{Path: path.Join(FilesDir, p.Subscription.Root), Mode: 0o750, Group: webGroup})
	}
	config := path.Join(FilesDir, p.Config)
	engineFiles := []string{UnitFile}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		f := bundle.File{Path: path.Join(FilesDir, name), Mode: 0o600, Data: files[name]}
		if p.Subscription != nil && strings.HasPrefix(name, p.Subscription.Root+"/") {
			f.Mode, f.Group = 0o640, webGroup
		}
		if f.Path == config {
			engineFiles = append(engineFiles, f.Path)
		}
		b.Files = append(b.Files, f)
	}
	for _, name := range p.RuleSets {
		data, ok := ruleSets[name]
		if !ok {
			return nil, fmt.Errorf("rule set %s is missing", name)
		}
		f := path.Join(engine.RuleSetDir, name)
		b.Files = append(b.Files, bundle.File{Path: f, Mode: 0o644, Data: data})
		engineFiles = append(engineFiles, f)
	}

	unit, err := execute("princo.service", map[string]any{
		"Node":      p.Node,
		"Engine":    p.Engine,
		"ExecStart": strings.Join(e.command(config, "/var/lib/princo-"+p.Engine), " "),
		"Reloads":   e.reloads,
		"StateDir":  "princo-" + p.Engine,
	})
	if err != nil {
		return nil, err
	}
	b.Files = append(b.Files, bundle.File{Path: UnitFile, Mode: 0o644, Data: unit})
	units := []bundle.Unit{{Name: "princo.service", Files: engineFiles, Check: e.check(config)}}

	var nginxFiles []string
	if p.Mux != nil || hostStream {
		conf, err := execute("stream.conf", p)
		if err != nil {
			return nil, err
		}
		b.Files = append(b.Files, bundle.File{Path: StreamConf, Mode: 0o644, Data: conf})
		nginxFiles = append(nginxFiles, StreamConf)
	}
	if len(p.Certificates) > 0 {
		if err := addSite(b, p, true); err != nil {
			return nil, err
		}
		nginxFiles = append(nginxFiles, SiteConf)
	}
	if len(nginxFiles) > 0 {
		units = append(units, nginxUnit(nginxFiles))
	}
	// Whichever leaves TCP 443 goes first. Losing the multiplexer, nginx
	// restarts on the emptied StreamConf: reloaded, its old workers would
	// hold the port a while.
	if p.Mux == nil && hostStream {
		units[1].Reload = false
		slices.Reverse(units)
	}
	b.Units = units
	return b, nil
}

// Bootstrap is the partial bundle that has nginx answer the ACME
// challenges for the missing certificates, leaving the rest of the node.
func Bootstrap(p *host.Plan, missing []string) (*bundle.Bundle, error) {
	b := &bundle.Bundle{Format: bundle.Format, Node: p.Node, Partial: true, Dirs: []bundle.Dir{stateDir}}
	siteTLS := p.Subscription != nil && !slices.Contains(missing, p.Subscription.Domain)
	if err := addSite(b, p, siteTLS); err != nil {
		return nil, err
	}
	b.Units = append(b.Units, nginxUnit([]string{SiteConf}))
	return b, nil
}

// addSite adds nginx's sites, the ACME webroot and the certbot hook;
// siteTLS serves the subscription site, which needs its certificate.
func addSite(b *bundle.Bundle, p *host.Plan, siteTLS bool) error {
	var engineDomains []string
	for _, d := range p.Certificates {
		if p.Subscription == nil || d != p.Subscription.Domain {
			engineDomains = append(engineDomains, d)
		}
	}
	data := map[string]any{
		"EngineDomains": engineDomains,
		"Site":          p.Subscription,
		"SiteTLS":       siteTLS,
		"ACMEDir":       ACMEDir,
		"CertDir":       engine.CertDir,
	}
	if p.Subscription != nil {
		data["Root"] = path.Join(FilesDir, p.Subscription.Root)
	}
	conf, err := execute("site.conf", data)
	if err != nil {
		return err
	}
	hook, err := execute("certbot-hook", map[string]any{
		"Site":          p.Subscription,
		"EngineDomains": engineDomains,
		"CertDir":       engine.CertDir,
	})
	if err != nil {
		return err
	}
	b.Dirs = append(b.Dirs, bundle.Dir{Path: ACMEDir, Mode: 0o755})
	b.Files = append(b.Files,
		bundle.File{Path: SiteConf, Mode: 0o644, Data: conf},
		bundle.File{Path: CertbotHook, Mode: 0o755, Data: hook},
	)
	return nil
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

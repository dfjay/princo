// Package deploy runs a node on a Debian or Ubuntu host over SSH. Build
// turns the node's plan and rendered files into the bundle the host
// applies (bundle.Host): the files, a systemd unit running the engine,
// nginx for the SNI multiplexer, ACME challenges and the subscription
// site, and a certbot hook. Deployer prepares the host, issues the
// certificates it lacks with a Bootstrap bundle, and applies the node's.
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
	// FilesDir holds the node's rendered files.
	FilesDir = "/var/lib/princo/files"
	// ACMEDir is the webroot certbot answers HTTP-01 challenges from.
	ACMEDir  = "/var/lib/princo/acme"
	UnitFile = "/etc/systemd/system/princo.service"
	// StreamConf is in modules-enabled because Debian's nginx.conf includes
	// that at the top level, the only place for a stream block short of
	// editing nginx.conf.
	StreamConf = "/etc/nginx/modules-enabled/99-princo-stream.conf"
	SiteConf   = "/etc/nginx/sites-enabled/princo.conf"
	// CertbotHook links the certificates certbot renews into engine.CertDir.
	CertbotHook = "/etc/letsencrypt/renewal-hooks/deploy/princo"
)

// stateDir is passed through by nginx to the site and the ACME webroot.
var stateDir = bundle.Dir{Path: bundle.StateDir, Mode: 0o755}

// webGroup is the group Debian's nginx runs as.
const webGroup = "www-data"

//go:embed templates
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{"q": shellQuote}).ParseFS(templateFS, "templates/*"))

// Build is the bundle of node p.Node: files are its rendered files
// (host.Files) and ruleSets the content of each of p.RuleSets. It needs
// the host to have the plan's certificates (see Bootstrap).
func Build(p *host.Plan, files, ruleSets map[string][]byte) (*bundle.Bundle, error) {
	e, ok := engines[p.Engine]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s yet", p.Engine)
	}
	b := &bundle.Bundle{Format: bundle.Format, Node: p.Node, Dirs: []bundle.Dir{stateDir}}

	filesDir := bundle.Dir{Path: FilesDir, Mode: 0o700}
	if p.Subscription != nil {
		// nginx passes through to the site.
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
	// The engine goes first: when the node gains the multiplexer, it holds
	// TCP 443 until it restarts on the new config.
	b.Units = append(b.Units, bundle.Unit{Name: "princo.service", Enable: true, Files: engineFiles, Check: e.check(config)})

	var nginxFiles []string
	if p.Mux != nil {
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
		b.Units = append(b.Units, nginxUnit(nginxFiles))
	}
	return b, nil
}

// Bootstrap is the partial bundle that has nginx answer the ACME
// challenges for the certificates the host lacks, missing, and leaves the
// rest of the node as it is.
func Bootstrap(p *host.Plan, missing []string) (*bundle.Bundle, error) {
	b := &bundle.Bundle{Format: bundle.Format, Node: p.Node, Partial: true, Dirs: []bundle.Dir{stateDir}}
	siteTLS := p.Subscription != nil && !slices.Contains(missing, p.Subscription.Domain)
	if err := addSite(b, p, siteTLS); err != nil {
		return nil, err
	}
	b.Units = append(b.Units, nginxUnit([]string{SiteConf}))
	return b, nil
}

// addSite adds nginx's sites, the ACME webroot and the certbot hook; with
// siteTLS, the subscription site over HTTPS, which needs its certificate.
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
	hook, err := execute("certbot-hook", map[string]any{"Domains": p.Certificates, "CertDir": engine.CertDir})
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
	return bundle.Unit{
		Name:   "nginx.service",
		Enable: true,
		Files:  files,
		Reload: true,
		Check:  []string{"nginx", "-t", "-q"},
	}
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

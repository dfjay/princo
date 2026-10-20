package deploy

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/host"
)

// Remote runs shell scripts as root on a node's host.
type Remote interface {
	Run(ctx context.Context, script string, stdin io.Reader, stdout io.Writer) error
}

// Deployer brings a node's host to the node's bundle.
type Deployer struct {
	Remote Remote
	// Out gets what applying the bundle changed; Log a line per step and
	// the output of the host's tools.
	Out, Log io.Writer
	// Version is this princo's version.
	Version string
	// Deb, when set, is the princo .deb to install on the host, whatever
	// princo it runs.
	Deb []byte
	// Release gives the .deb of a released princo for a Debian
	// architecture, e.g. ReleaseDeb.
	Release func(ctx context.Context, version, arch string) ([]byte, error)
}

// facts are what probe.sh tells about the host.
type facts struct {
	arch string
	// princo is the version the host runs, empty without princo.
	princo string
	// node is the node the host runs, empty before its first deploy.
	node string
	// missing are the plan's certificates the host lacks.
	missing []string
}

// Deploy installs the packages the node needs and princo on its host,
// issues the certificates the host lacks, and applies the node's bundle.
func (d *Deployer) Deploy(ctx context.Context, p *host.Plan, files, ruleSets map[string][]byte) error {
	e, ok := engines[p.Engine]
	if !ok {
		return fmt.Errorf("princo deploy can't run engine %s yet", p.Engine)
	}
	f, err := d.probe(ctx, p)
	if err != nil {
		return err
	}
	d.logf("installing packages")
	if err := d.provision(ctx, p, e); err != nil {
		return err
	}
	if err := d.installPrinco(ctx, f); err != nil {
		return err
	}
	if len(f.missing) > 0 {
		b, err := Bootstrap(p, f.missing)
		if err != nil {
			return err
		}
		d.logf("serving ACME challenges")
		if err := d.apply(ctx, b, false); err != nil {
			return err
		}
		for _, domain := range f.missing {
			d.logf("issuing a certificate for %s", domain)
			script, err := execute("issue.sh", map[string]any{
				"Domain":  domain,
				"Email":   p.ACMEEmail,
				"ACMEDir": ACMEDir,
				"Hook":    CertbotHook,
			})
			if err != nil {
				return err
			}
			if err := d.Remote.Run(ctx, string(script), nil, d.Log); err != nil {
				return fmt.Errorf("certificate for %s: %w", domain, err)
			}
		}
	}
	b, err := Build(p, files, ruleSets)
	if err != nil {
		return err
	}
	d.logf("applying node %s", p.Node)
	return d.apply(ctx, b, false)
}

// Check prints what Deploy would change in the host's files, and changes
// nothing. The host must run princo already.
func (d *Deployer) Check(ctx context.Context, p *host.Plan, files, ruleSets map[string][]byte) error {
	f, err := d.probe(ctx, p)
	if err != nil {
		return err
	}
	if f.princo == "" {
		return errors.New("the host has no princo yet; deploying without --dry-run installs it")
	}
	b, err := Build(p, files, ruleSets)
	if err != nil {
		return err
	}
	return d.apply(ctx, b, true)
}

func (d *Deployer) probe(ctx context.Context, p *host.Plan) (facts, error) {
	script, err := execute("probe.sh", map[string]any{
		"Certificates": p.Certificates,
		"CertDir":      engine.CertDir,
		"StateFile":    bundle.StateFile,
	})
	if err != nil {
		return facts{}, err
	}
	var out bytes.Buffer
	if err := d.Remote.Run(ctx, string(script), nil, &out); err != nil {
		return facts{}, err
	}
	var f facts
	for line := range strings.Lines(out.String()) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch key {
		case "arch":
			f.arch = value
		case "princo":
			f.princo = value
		case "node":
			f.node = value
		case "missing":
			f.missing = append(f.missing, value)
		}
	}
	if f.arch == "" {
		return f, errors.New("the host didn't tell its architecture")
	}
	if f.node != "" && f.node != p.Node {
		return f, bundle.OtherNodeError(f.node, p.Node)
	}
	return f, nil
}

func (d *Deployer) provision(ctx context.Context, p *host.Plan, e engineSpec) error {
	pkgs := []string{e.pkg}
	tcp := slices.Clone(p.TCPPorts)
	if p.Mux != nil || len(p.Certificates) > 0 {
		pkgs = append(pkgs, "nginx")
	}
	if p.Mux != nil {
		pkgs = append(pkgs, "libnginx-mod-stream")
	}
	if len(p.Certificates) > 0 {
		// HTTP-01 challenges come on port 80.
		pkgs = append(pkgs, "certbot")
		tcp = append(tcp, 80)
	}
	script, err := execute("provision.sh", map[string]any{
		"Repo":        e.repo,
		"Packages":    pkgs,
		"PackageUnit": e.pkgUnit,
		"TCP":         tcp,
		"UDP":         p.UDPPorts,
	})
	if err != nil {
		return err
	}
	return d.Remote.Run(ctx, string(script), nil, d.Log)
}

const installDeb = `set -eu
f=$(mktemp --suffix=.deb)
trap 'rm -f "$f"' EXIT
cat >"$f"
dpkg -i "$f" >/dev/null
`

// installPrinco puts this princo's release on the host, or Deb. A princo
// between releases has no .deb, so it goes on with any princo the host
// has: the bundle format guards against one too old.
func (d *Deployer) installPrinco(ctx context.Context, f facts) error {
	deb := d.Deb
	switch {
	case deb != nil:
	case f.princo == d.Version:
		return nil
	case !strings.Contains(d.Version, "+"):
		var err error
		if deb, err = d.Release(ctx, d.Version, f.arch); err != nil {
			return err
		}
	case f.princo == "":
		return fmt.Errorf("this princo, %s, isn't a release, so there's no .deb of it for the host; pass --princo-deb (just snapshot builds one)", d.Version)
	default:
		d.logf("the host runs princo %s, this is %s", f.princo, d.Version)
		return nil
	}
	d.logf("installing princo on the host")
	return d.Remote.Run(ctx, installDeb, bytes.NewReader(deb), d.Log)
}

func (d *Deployer) apply(ctx context.Context, b *bundle.Bundle, check bool) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	cmd := "princo host apply"
	if check {
		cmd += " --check"
	}
	return d.Remote.Run(ctx, cmd, bytes.NewReader(data), d.Out)
}

func (d *Deployer) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(d.Log, "deploy: "+format+"\n", args...)
}

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

type Deployer struct {
	Remote Remote
	// Out gets the changes the bundle made; Log the steps and the host's
	// tools' output.
	Out, Log io.Writer
	// Version is this princo's.
	Version string
	// Deb, when set, is installed on the host whatever princo it has.
	Deb []byte
	// Release gives a released princo's .deb for a Debian architecture.
	Release func(ctx context.Context, version, arch string) ([]byte, error)
	// Fetch downloads an engine without a package.
	Fetch func(ctx context.Context, url string) ([]byte, error)
}

// facts are what probe.sh tells; princo, engine (its binary's version)
// and node are empty when the host has none.
type facts struct {
	arch, princo, engine, node string
	missing                    []string
	stream                     bool
}

// Deploy installs the node's packages and princo, issues the certificates
// the host lacks, and applies the node's bundle.
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
	if err := d.installEngine(ctx, f, e); err != nil {
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
	b, err := Build(p, files, ruleSets, f.stream)
	if err != nil {
		return err
	}
	d.logf("applying node %s", p.Node)
	return d.apply(ctx, b, false)
}

// Check prints what Deploy would change in the host's files.
func (d *Deployer) Check(ctx context.Context, p *host.Plan, files, ruleSets map[string][]byte) error {
	f, err := d.probe(ctx, p)
	if err != nil {
		return err
	}
	if f.princo == "" {
		return errors.New("the host has no princo yet; deploying without --dry-run installs it")
	}
	b, err := Build(p, files, ruleSets, f.stream)
	if err != nil {
		return err
	}
	return d.apply(ctx, b, true)
}

func (d *Deployer) probe(ctx context.Context, p *host.Plan) (facts, error) {
	var bin string
	if b := engines[p.Engine].binary; b != nil {
		bin = b.Path
	}
	script, err := execute("probe.sh", map[string]any{
		"Binary":       bin,
		"Certificates": p.Certificates,
		"CertDir":      engine.CertDir,
		"StateFile":    bundle.StateFile,
		"StreamConf":   StreamConf,
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
		case "engine":
			f.engine = value
		case "node":
			f.node = value
		case "missing":
			f.missing = append(f.missing, value)
		case "stream":
			f.stream = true
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
	var pkgs []string
	if e.pkg != "" {
		pkgs = append(pkgs, e.pkg)
	}
	tcp := slices.Clone(p.TCPPorts)
	if p.Mux != nil || len(p.Certificates) > 0 {
		pkgs = append(pkgs, "nginx")
	}
	if p.Mux != nil {
		pkgs = append(pkgs, "libnginx-mod-stream")
	}
	if len(p.Certificates) > 0 {
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

// installBinary replaces the executable bin with stdin.
const installBinary = `set -eu
bin=%s
install -d -m 0755 "$(dirname "$bin")"
f=$(mktemp "$bin.XXXXXX")
trap 'rm -f "$f"' EXIT
cat >"$f"
chmod 0755 "$f"
mv -f "$f" "$bin"
`

// installEngine puts the engine's binary on the host, unless it has it.
func (d *Deployer) installEngine(ctx context.Context, f facts, e engineSpec) error {
	b := e.binary
	if b == nil || f.engine == b.Version {
		return nil
	}
	z, ok := b.Zips[f.arch]
	if !ok {
		return fmt.Errorf("there's no %s %s for %s", b.Member, b.Version, f.arch)
	}
	data, err := d.Fetch(ctx, z.URL)
	if err != nil {
		return err
	}
	exe, err := b.extract(z, data)
	if err != nil {
		return err
	}
	d.logf("installing %s %s on the host", b.Member, b.Version)
	return d.Remote.Run(ctx, fmt.Sprintf(installBinary, shellQuote(b.Path)), bytes.NewReader(exe), d.Log)
}

const installDeb = `set -eu
f=$(mktemp --suffix=.deb)
trap 'rm -f "$f"' EXIT
cat >"$f"
dpkg -i "$f" >/dev/null
`

// installPrinco puts this princo's release or Deb on the host. A build
// between releases has no .deb; it makes do with the host's princo, as the
// bundle format refuses one too old.
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

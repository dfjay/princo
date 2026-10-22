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

// facts are what probe.sh tells; princo and node are empty when the host
// has none.
type facts struct {
	arch, princo, node string
	// engine tells that the host has the engine's release.
	engine  bool
	missing []string
	// linked are certificates an older princo linked into certbot's directories.
	linked []string
	stream bool
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
	if err := d.provision(ctx, p); err != nil {
		return err
	}
	if err := d.installEngine(ctx, f, e); err != nil {
		return err
	}
	if err := d.installPrinco(ctx, f); err != nil {
		return err
	}
	if err := d.copyLinked(ctx, p, f.linked); err != nil {
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
	if err := d.apply(ctx, b, false); err != nil {
		return err
	}
	return d.Remote.Run(ctx, fmt.Sprintf(pruneReleases, shellQuote(engineRoot), shellQuote(e.dir())), nil, d.Log)
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
	script, err := execute("probe.sh", map[string]any{
		"Engine":       engines[p.Engine].bin(),
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
			f.engine = true
		case "node":
			f.node = value
		case "missing":
			f.missing = append(f.missing, value)
		case "linked":
			f.linked = append(f.linked, value)
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

// copyLinked replaces linked certificates with copies, which the engine
// can read without access to certbot's directories.
func (d *Deployer) copyLinked(ctx context.Context, p *host.Plan, domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	hook, err := certbotHook(p)
	if err != nil {
		return err
	}
	for _, domain := range domains {
		d.logf("copying the certificate for %s", domain)
		script := "RENEWED_LINEAGE=" + shellQuote("/etc/letsencrypt/live/"+domain) + "\nexport RENEWED_LINEAGE\n" + string(hook)
		if err := d.Remote.Run(ctx, script, nil, d.Log); err != nil {
			return fmt.Errorf("certificate for %s: %w", domain, err)
		}
	}
	return nil
}

func (d *Deployer) provision(ctx context.Context, p *host.Plan) error {
	var pkgs []string
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
		"Packages": pkgs,
		"TCP":      tcp,
		"UDP":      p.UDPPorts,
		"Group":    engineGroup,
	})
	if err != nil {
		return err
	}
	return d.Remote.Run(ctx, string(script), nil, d.Log)
}

// installRelease unpacks the tar on stdin into dir, whole or not at all.
const installRelease = `set -eu
dir=%s
install -d -m 0755 "$(dirname "$dir")"
tmp=$(mktemp -d "$dir.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
tar -x -C "$tmp" --no-same-owner
chmod 0755 "$tmp"
rm -rf "$dir"
mv "$tmp" "$dir"
`

// pruneReleases removes the engine releases but the one at keep, once
// the node no longer needs them to roll back.
const pruneReleases = `set -eu
for dir in %s/*; do
	[ "$dir" = %s ] || rm -rf "$dir"
done
`

// installEngine puts the engine's release on the host, unless it has it.
func (d *Deployer) installEngine(ctx context.Context, f facts, e engineSpec) error {
	if f.engine {
		return nil
	}
	name := e.release.Files[0]
	a, ok := e.archive(f.arch)
	if !ok {
		return fmt.Errorf("there's no %s %s for %s", name, e.version, f.arch)
	}
	data, err := d.Fetch(ctx, a.URL)
	if err != nil {
		return err
	}
	files, err := e.release.extract(a, data)
	if err != nil {
		return err
	}
	d.logf("installing %s %s on the host", name, e.version)
	return d.Remote.Run(ctx, fmt.Sprintf(installRelease, shellQuote(e.dir())), bytes.NewReader(files), d.Log)
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

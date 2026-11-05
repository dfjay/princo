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
	"github.com/dfjay/princo/internal/fleet"
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
	// engine and lego tell that the host has their releases.
	engine, lego bool
	// openssl tells that it could read the certificates' domains.
	openssl bool
	// missing are the ACME certificates to issue.
	missing []string
	// linked are certificates an older princo linked into certbot's directories.
	linked  []string
	earlier Earlier
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
	// With openssl installed, the probe reads the domains of the
	// certificates the host has.
	if !f.openssl && slices.ContainsFunc(certificates(p, fleet.CertHTTP, fleet.CertDNS), func(c host.Certificate) bool {
		return !slices.Contains(f.missing, c.Name) && !slices.Contains(f.linked, c.Name)
	}) {
		if f, err = d.probe(ctx, p); err != nil {
			return err
		}
	}
	if err := d.installEngine(ctx, f, e); err != nil {
		return err
	}
	if len(certificates(p, fleet.CertDNS)) > 0 {
		if err := d.installLego(ctx, f); err != nil {
			return err
		}
	}
	if err := d.installPrinco(ctx, f); err != nil {
		return err
	}
	if err := d.copyLinked(ctx, p, f.linked); err != nil {
		return err
	}
	if len(f.missing) > 0 {
		b, err := Bootstrap(p, files, f.missing)
		if err != nil {
			return err
		}
		d.logf("readying the host to issue certificates")
		if err := d.apply(ctx, b, false); err != nil {
			return err
		}
		for _, name := range f.missing {
			if err := d.issue(ctx, p, name); err != nil {
				return fmt.Errorf("certificate %s: %w", name, err)
			}
		}
	}
	b, err := Build(p, files, ruleSets, f.earlier)
	if err != nil {
		return err
	}
	d.logf("applying node %s", p.Node)
	if err := d.apply(ctx, b, false); err != nil {
		return err
	}
	return d.cleanup(ctx, p, e)
}

// issue issues certificate name: with certbot over HTTP-01, else lego.
func (d *Deployer) issue(ctx context.Context, p *host.Plan, name string) error {
	c, ok := certificate(p, name)
	if !ok {
		return errors.New("the plan has no such certificate")
	}
	d.logf("issuing certificate %s for %s", c.Name, strings.Join(c.Domains, ", "))
	// Unattended, lego waits a random while before renewing.
	script := "LEGO_NO_RANDOM_SLEEP=true " + LegoScript + " " + shellQuote(c.Name)
	if c.Source == fleet.CertHTTP {
		data, err := execute("issue.sh", map[string]any{
			"Name":    c.Name,
			"Domains": strings.Join(c.Domains, ","),
			"Email":   p.ACMEEmail,
			"ACMEDir": ACMEDir,
			"Hook":    CertbotHook,
		})
		if err != nil {
			return err
		}
		script = string(data)
	}
	return d.Remote.Run(ctx, script, nil, d.Log)
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
	b, err := Build(p, files, ruleSets, f.earlier)
	if err != nil {
		return err
	}
	return d.apply(ctx, b, true)
}

func (d *Deployer) probe(ctx context.Context, p *host.Plan) (facts, error) {
	script, err := execute("probe.sh", map[string]any{
		"Engine":       engines[p.Engine].bin(),
		"Certificates": certificates(p, fleet.CertHTTP, fleet.CertDNS),
		"Lego":         legoBin(),
		"CertDir":      engine.CertDir,
		"StateFile":    bundle.StateFile,
		"StreamConf":   StreamConf,
		"SiteConf":     SiteConf,
		"LoopbackUnit": LoopbackUnitFile,
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
		case "lego":
			f.lego = true
		case "openssl":
			f.openssl = true
		case "node":
			f.node = value
		case "missing":
			f.missing = append(f.missing, value)
		case "linked":
			f.linked = append(f.linked, value)
		case "sans":
			name, sans, _ := strings.Cut(value, " ")
			if !sameDomains(p, name, sans) {
				f.missing = append(f.missing, name)
			}
		case "stream":
			f.earlier.Stream = true
		case "site":
			f.earlier.Site = true
		case "loopback":
			f.earlier.Loopback = true
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

// sameDomains tells whether certificate name, whose subjectAltName openssl
// prints as sans (DNS:a,DNS:b), has the plan's domains.
func sameDomains(p *host.Plan, name, sans string) bool {
	c, ok := certificate(p, name)
	if !ok {
		return true
	}
	var have []string
	for san := range strings.SplitSeq(sans, ",") {
		if d, ok := strings.CutPrefix(san, "DNS:"); ok {
			have = append(have, d)
		}
	}
	return slices.Equal(domainSet(have), domainSet(c.Domains))
}

func domainSet(domains []string) []string {
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = strings.ToLower(d)
	}
	slices.Sort(out)
	return slices.Compact(out)
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
	if p.Mux != nil || needsSite(p) {
		pkgs = append(pkgs, "nginx")
	}
	if p.Mux != nil {
		pkgs = append(pkgs, "libnginx-mod-stream")
	}
	if p.Mux != nil && p.Mux.Loopback != nil {
		pkgs = append(pkgs, "iproute2")
	}
	if len(certificates(p, fleet.CertHTTP)) > 0 {
		pkgs = append(pkgs, "certbot")
	}
	if len(certificates(p, fleet.CertHTTP, fleet.CertDNS)) > 0 {
		// For probe.sh to read the certificates' domains.
		pkgs = append(pkgs, "openssl")
	}
	script, err := execute("provision.sh", map[string]any{
		"Packages": pkgs,
		"Ports":    ports(p),
		"Group":    engineGroup,
	})
	if err != nil {
		return err
	}
	return d.Remote.Run(ctx, string(script), nil, d.Log)
}

// cleanup removes what the applied node no longer needs: the other engine
// releases, kept for a rollback until now, and the ufw rules princo opened
// for ports it stopped using.
func (d *Deployer) cleanup(ctx context.Context, p *host.Plan, e engineSpec) error {
	keepLego := ""
	if len(certificates(p, fleet.CertDNS)) > 0 {
		keepLego = legoDir()
	}
	script, err := execute("cleanup.sh", map[string]any{
		"Root":      engineRoot,
		"Keep":      e.dir(),
		"LegoRoot":  legoRoot,
		"KeepLego":  keepLego,
		"LegoTimer": LegoTimer,
		"Ports":     ports(p),
	})
	if err != nil {
		return err
	}
	return d.Remote.Run(ctx, string(script), nil, d.Log)
}

// ports are the node's ufw rules, like 443/tcp; 80 serves ACME challenges.
func ports(p *host.Plan) []string {
	var out []string
	for _, port := range p.TCPPorts {
		out = append(out, fmt.Sprintf("%d/tcp", port))
	}
	if len(certificates(p, fleet.CertHTTP)) > 0 {
		out = append(out, "80/tcp")
	}
	for _, port := range p.UDPPorts {
		out = append(out, fmt.Sprintf("%d/udp", port))
	}
	return out
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

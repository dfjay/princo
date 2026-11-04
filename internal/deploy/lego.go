package deploy

import (
	"bytes"
	"context"
	"fmt"
	"path"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
)

// lego issues the DNS-01 certificates; certbot keeps HTTP-01.
var lego = struct {
	version string
	release release
}{
	version: "5.6.0",
	release: release{
		URL: "https://github.com/go-acme/lego/releases/download/v{version}/lego_v{version}_linux_{arch}.tar.gz",
		SHA256: map[string]string{
			"amd64": "f02fc11b6f56b97e387fa7caa0268f86f5a336953b22458e6430e4651fea439a",
			"arm64": "34d87a6552d69390c4a4560237045c47713a8e148d899e16db0e97040894ed1f",
		},
		Files: []string{"lego"},
	},
}

// Paths of lego on the host.
const (
	legoRoot = "/usr/local/lib/princo-lego"
	// LegoDir is lego's account and certificates.
	LegoDir = "/var/lib/princo/lego"
	// LegoScript issues or renews the named DNS-01 certificates, or all.
	LegoScript  = "/usr/local/sbin/princo-lego"
	LegoService = "/etc/systemd/system/princo-lego.service"
	LegoTimer   = "/etc/systemd/system/princo-lego.timer"
)

func legoDir() string { return path.Join(legoRoot, "lego-"+lego.version) }
func legoBin() string { return path.Join(legoDir(), "lego") }

// dnsEnv is a DNS-01 certificate's credentials among the rendered files.
func dnsEnv(name string) string { return path.Join(host.CertsDir, name, "dns.env") }

// addLego adds the script and the daily timer that renews with it.
func addLego(b *bundle.Bundle, p *host.Plan) error {
	script, err := execute("lego.sh", map[string]any{
		"Lego":         legoBin(),
		"Dir":          LegoDir,
		"Email":        p.ACMEEmail,
		"Hook":         CertbotHook,
		"CertDir":      engine.CertDir,
		"Certificates": certificates(p, fleet.CertDNS),
		"Env":          func(name string) string { return path.Join(FilesDir, dnsEnv(name)) },
	})
	if err != nil {
		return err
	}
	service, err := execute("princo-lego.service", map[string]any{"Script": LegoScript})
	if err != nil {
		return err
	}
	timer, err := execute("princo-lego.timer", nil)
	if err != nil {
		return err
	}
	b.Dirs = append(b.Dirs, bundle.Dir{Path: LegoDir, Mode: 0o700})
	b.Files = append(b.Files,
		bundle.File{Path: LegoScript, Mode: 0o755, Data: script},
		bundle.File{Path: LegoService, Mode: 0o644, Data: service},
		bundle.File{Path: LegoTimer, Mode: 0o644, Data: timer},
	)
	return nil
}

// installLego puts the pinned lego on the host, unless it has it.
func (d *Deployer) installLego(ctx context.Context, f facts) error {
	if f.lego {
		return nil
	}
	a, ok := lego.release.archive(lego.version, f.arch)
	if !ok {
		return fmt.Errorf("there's no lego %s for %s", lego.version, f.arch)
	}
	data, err := d.Fetch(ctx, a.URL)
	if err != nil {
		return err
	}
	files, err := lego.release.extract(a, data)
	if err != nil {
		return err
	}
	d.logf("installing lego %s on the host", lego.version)
	return d.Remote.Run(ctx, fmt.Sprintf(installRelease, shellQuote(legoDir())), bytes.NewReader(files), d.Log)
}

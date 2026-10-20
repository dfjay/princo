package deploy

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/bundle"
)

// fakeRemote answers probe.sh with probe and records what else runs.
type fakeRemote struct {
	t     *testing.T
	probe string
	// steps names each script that ran: probe, provision, install,
	// apply, check, or issue <domain>.
	steps   []string
	bundles []*bundle.Bundle
	deb     []byte
}

func (r *fakeRemote) Run(_ context.Context, script string, stdin io.Reader, stdout io.Writer) error {
	// Every script must at least parse.
	require.NoError(r.t, exec.Command("sh", "-n", "-c", script).Run(), script)
	var in []byte
	if stdin != nil {
		var err error
		in, err = io.ReadAll(stdin)
		require.NoError(r.t, err)
	}
	switch {
	case strings.Contains(script, "dpkg --print-architecture"):
		r.steps = append(r.steps, "probe")
		_, err := io.WriteString(stdout, r.probe)
		return err
	case strings.Contains(script, "apt-get install"):
		r.steps = append(r.steps, "provision")
	case strings.Contains(script, "dpkg -i"):
		r.steps = append(r.steps, "install")
		r.deb = in
	case strings.HasPrefix(script, "princo host apply"):
		var b bundle.Bundle
		require.NoError(r.t, json.Unmarshal(in, &b))
		r.bundles = append(r.bundles, &b)
		if strings.HasSuffix(script, "--check") {
			r.steps = append(r.steps, "check")
		} else {
			r.steps = append(r.steps, "apply")
		}
	case strings.Contains(script, "certbot certonly"):
		_, domain, _ := strings.Cut(script, "--domains '")
		domain, _, _ = strings.Cut(domain, "'")
		r.steps = append(r.steps, "issue "+domain)
	default:
		r.t.Fatalf("unexpected script:\n%s", script)
	}
	return nil
}

func newDeployer(r *fakeRemote, version string) (*Deployer, *bytes.Buffer) {
	var log bytes.Buffer
	return &Deployer{
		Remote:  r,
		Out:     io.Discard,
		Log:     &log,
		Version: version,
		Release: func(_ context.Context, v, arch string) ([]byte, error) {
			return []byte("deb " + v + " " + arch), nil
		},
	}, &log
}

func TestDeploy_FreshHost(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch arm64\nmissing naive-de.example.com\nmissing subs.example.com\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "de")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))

	require.Equal(t, []string{
		"probe", "provision", "install",
		"apply", "issue naive-de.example.com", "issue subs.example.com",
		"apply",
	}, r.steps)
	require.Equal(t, "deb 0.2.0 arm64", string(r.deb))
	require.True(t, r.bundles[0].Partial, "the engine waits for the certificates")
	require.Equal(t, []string{"princo.service", "nginx.service"}, unitNames(r.bundles[1]))
}

func TestDeploy_UpToDate(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nprinco 0.2.0\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "us")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "apply"}, r.steps)
}

func TestDeploy_OlderPrinco(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nprinco 0.1.1\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "us")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "install", "apply"}, r.steps)
	require.Equal(t, "deb 0.2.0 amd64", string(r.deb))
}

func TestDeploy_DevBuild(t *testing.T) {
	p, files, ruleSets := plan(t, "us")

	r := &fakeRemote{t: t, probe: "arch amd64\n"}
	d, _ := newDeployer(r, "0.2.0+abc1234")
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "pass --princo-deb")

	r = &fakeRemote{t: t, probe: "arch amd64\nprinco 0.1.1\n"}
	d, log := newDeployer(r, "0.2.0+abc1234")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "apply"}, r.steps)
	require.Contains(t, log.String(), "the host runs princo 0.1.1, this is 0.2.0+abc1234")

	r = &fakeRemote{t: t, probe: "arch amd64\nprinco 0.1.1\n"}
	d, _ = newDeployer(r, "0.2.0+abc1234")
	d.Deb = []byte("snapshot")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, "snapshot", string(r.deb))
}

func TestDeploy_OtherNode(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nnode us\nprinco 0.2.0\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "de")
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "this host runs node us, not de")
	require.Equal(t, []string{"probe"}, r.steps, "nothing changes on the host")

	r = &fakeRemote{t: t, probe: "arch amd64\nnode de\nprinco 0.2.0\n"}
	d, _ = newDeployer(r, "0.2.0")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
}

func TestCheck(t *testing.T) {
	p, files, ruleSets := plan(t, "de")

	r := &fakeRemote{t: t, probe: "arch amd64\nprinco 0.2.0\nmissing subs.example.com\n"}
	d, _ := newDeployer(r, "0.2.0")
	require.NoError(t, d.Check(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "check"}, r.steps)
	require.Equal(t, []string{"princo.service", "nginx.service"}, unitNames(r.bundles[0]), "the node as it will be")

	r = &fakeRemote{t: t, probe: "arch amd64\n"}
	d, _ = newDeployer(r, "0.2.0")
	require.ErrorContains(t, d.Check(t.Context(), p, files, ruleSets), "the host has no princo yet")
}

func TestProbe_Certificates(t *testing.T) {
	var script string
	d, _ := newDeployer(nil, "0.2.0")
	d.Remote = remoteFunc(func(s string) { script = s })
	p, _, _ := plan(t, "de")
	_, err := d.probe(t.Context(), p)
	require.ErrorContains(t, err, "didn't tell its architecture")
	require.Contains(t, script, "[ -s '/var/lib/princo/certs/subs.example.com/fullchain.pem' ] && [ -s '/var/lib/princo/certs/subs.example.com/key.pem' ] || echo missing 'subs.example.com'")
}

func TestProvision(t *testing.T) {
	r := &fakeRemote{t: t}
	d, _ := newDeployer(r, "0.2.0")
	var script string
	d.Remote = remoteFunc(func(s string) { script = s })
	p, _, _ := plan(t, "de")
	require.NoError(t, d.provision(t.Context(), p, engines[p.Engine]))
	require.Contains(t, script, "for p in 'sing-box' 'nginx' 'libnginx-mod-stream' 'certbot'; do")
	require.Contains(t, script, "ufw allow 443/tcp")
	require.Contains(t, script, "ufw allow 80/tcp")
	require.Contains(t, script, "ufw allow 443/udp")
	require.Contains(t, script, "-----END PGP PUBLIC KEY BLOCK-----\nPRINCO_EOF\n")
	require.Contains(t, script, "chmod 0644 /etc/apt/keyrings/sagernet.asc /etc/apt/sources.list.d/sagernet.sources")
	require.NoError(t, exec.Command("sh", "-n", "-c", script).Run())

	p, _, _ = plan(t, "us")
	require.NoError(t, d.provision(t.Context(), p, engines[p.Engine]))
	require.Contains(t, script, "for p in 'sing-box'; do")
	require.NotContains(t, script, "/udp")
}

type remoteFunc func(script string)

func (f remoteFunc) Run(_ context.Context, script string, _ io.Reader, _ io.Writer) error {
	f(script)
	return nil
}

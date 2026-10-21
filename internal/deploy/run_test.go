package deploy

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
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
	release []byte
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
	case strings.Contains(script, `tar -x -C "$tmp"`):
		r.steps = append(r.steps, "install engine")
		r.release = in
	case strings.Contains(script, "for dir in"):
		r.steps = append(r.steps, "prune")
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
	r := &fakeRemote{t: t, probe: "arch arm64\nengine\nmissing naive-de.example.com\nmissing subs.example.com\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "de")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))

	require.Equal(t, []string{
		"probe", "provision", "install",
		"apply", "issue naive-de.example.com", "issue subs.example.com",
		"apply", "prune",
	}, r.steps)
	require.Equal(t, "deb 0.2.0 arm64", string(r.deb))
	require.True(t, r.bundles[0].Partial, "the engine waits for the certificates")
	require.Equal(t, []string{"princo.service", "nginx.service"}, unitNames(r.bundles[1]))
}

func TestDeploy_UpToDate(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.2.0\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "us")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "apply", "prune"}, r.steps)
}

func TestDeploy_OlderPrinco(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.1.1\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "us")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "install", "apply", "prune"}, r.steps)
	require.Equal(t, "deb 0.2.0 amd64", string(r.deb))
}

func TestDeploy_DevBuild(t *testing.T) {
	p, files, ruleSets := plan(t, "us")

	r := &fakeRemote{t: t, probe: "arch amd64\nengine\n"}
	d, _ := newDeployer(r, "0.2.0+abc1234")
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "pass --princo-deb")

	r = &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.1.1\n"}
	d, log := newDeployer(r, "0.2.0+abc1234")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "apply", "prune"}, r.steps)
	require.Contains(t, log.String(), "the host runs princo 0.1.1, this is 0.2.0+abc1234")

	r = &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.1.1\n"}
	d, _ = newDeployer(r, "0.2.0+abc1234")
	d.Deb = []byte("snapshot")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, "snapshot", string(r.deb))
}

func TestDeploy_OtherNode(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nnode us\nprinco 0.2.0\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "de")
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "this host runs node us, not de")
	require.Equal(t, []string{"probe"}, r.steps, "nothing changes on the host")

	r = &fakeRemote{t: t, probe: "arch amd64\nengine\nnode de\nprinco 0.2.0\n"}
	d, _ = newDeployer(r, "0.2.0")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
}

func TestDeploy_MuxRemoved(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nnode us\nstream\nprinco 0.2.0\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "us")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"nginx.service", "princo.service"}, unitNames(r.bundles[0]))
}

func TestCheck(t *testing.T) {
	p, files, ruleSets := plan(t, "de")

	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.2.0\nmissing subs.example.com\n"}
	d, _ := newDeployer(r, "0.2.0")
	require.NoError(t, d.Check(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "check"}, r.steps)
	require.Equal(t, []string{"princo.service", "nginx.service"}, unitNames(r.bundles[0]), "the node as it will be")

	r = &fakeRemote{t: t, probe: "arch amd64\nengine\n"}
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
	require.NoError(t, d.provision(t.Context(), p))
	require.Contains(t, script, "for p in 'nginx' 'libnginx-mod-stream' 'certbot'; do")
	require.Contains(t, script, "ufw allow 443/tcp")
	require.Contains(t, script, "ufw allow 80/tcp")
	require.Contains(t, script, "ufw allow 443/udp")
	require.NoError(t, exec.Command("sh", "-n", "-c", script).Run())

	p, _, _ = plan(t, "us")
	require.NoError(t, d.provision(t.Context(), p))
	require.Contains(t, script, "for p in; do")
	require.NotContains(t, script, "/udp")
	require.NoError(t, exec.Command("sh", "-n", "-c", script).Run())
}

// withRelease has engine name's release be the archive data, served at
// url, until the test ends.
func withRelease(t *testing.T, name, url string, data []byte) {
	t.Helper()
	sum := sha256.Sum256(data)
	old := engines[name]
	e := old
	e.release.URL = url
	e.release.SHA256 = map[string]string{"amd64": hex.EncodeToString(sum[:])}
	engines[name] = e
	t.Cleanup(func() { engines[name] = old })
}

// zipOf and tarGzOf archive files, each holding its own name.
func zipOf(t *testing.T, files ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range files {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte(name))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func tarGzOf(t *testing.T, files ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w := tar.NewWriter(gz)
	for _, name := range files {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(name))}))
		_, err := w.Write([]byte(name))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func TestDeploy_InstallsEngine(t *testing.T) {
	zipped := zipOf(t, "xray", "geoip.dat")
	withRelease(t, "xray", "https://example.com/xray.zip", zipped)

	p, files, ruleSets := plan(t, "fi")
	r := &fakeRemote{t: t, probe: "arch amd64\nprinco 0.2.0\n"}
	d, _ := newDeployer(r, "0.2.0")
	var fetched []string
	d.Fetch = func(_ context.Context, url string) ([]byte, error) {
		fetched = append(fetched, url)
		return zipped, nil
	}
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "install engine", "apply", "prune"}, r.steps)
	require.Equal(t, []string{"https://example.com/xray.zip"}, fetched)
	require.Equal(t, map[string]string{"xray": "xray"}, untar(t, r.release), "only the files the engine needs")

	r = &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.2.0\n"}
	d, _ = newDeployer(r, "0.2.0")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{"probe", "provision", "apply", "prune"}, r.steps, "the host has this release")

	r = &fakeRemote{t: t, probe: "arch arm64\nprinco 0.2.0\n"}
	d, _ = newDeployer(r, "0.2.0")
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "there's no xray 26.3.27 for arm64")

	r = &fakeRemote{t: t, probe: "arch amd64\nprinco 0.2.0\n"}
	d, _ = newDeployer(r, "0.2.0")
	d.Fetch = func(context.Context, string) ([]byte, error) { return []byte("tampered"), nil }
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "doesn't match its pinned SHA-256")
}

func TestRelease_TarGz(t *testing.T) {
	data := tarGzOf(t, "sing-box-1.14.3-linux-amd64/sing-box", "sing-box-1.14.3-linux-amd64/libcronet.so", "sing-box-1.14.3-linux-amd64/LICENSE")
	sum := sha256.Sum256(data)

	out, err := engines["sing-box"].release.extract(download{URL: "https://example.com/sb.tar.gz", SHA256: hex.EncodeToString(sum[:])}, data)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"sing-box":     "sing-box-1.14.3-linux-amd64/sing-box",
		"libcronet.so": "sing-box-1.14.3-linux-amd64/libcronet.so",
	}, untar(t, out))
}

func untar(t *testing.T, data []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		require.NoError(t, err)
		require.Equal(t, int64(0o755), h.Mode, h.Name)
		b, err := io.ReadAll(tr)
		require.NoError(t, err)
		out[h.Name] = string(b)
	}
}

type remoteFunc func(script string)

func (f remoteFunc) Run(_ context.Context, script string, _ io.Reader, _ io.Writer) error {
	f(script)
	return nil
}

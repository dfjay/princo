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
	"os"
	"os/exec"
	"path/filepath"
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
	// apply, check, issue <domain> or copy <domain>.
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
	case strings.HasPrefix(script, "RENEWED_LINEAGE="):
		lineage, _, _ := strings.Cut(strings.TrimPrefix(script, "RENEWED_LINEAGE='/etc/letsencrypt/live/"), "'")
		r.steps = append(r.steps, "copy "+lineage)
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

func TestDeploy_CopiesLinkedCertificates(t *testing.T) {
	r := &fakeRemote{t: t, probe: "arch amd64\nengine\nprinco 0.2.0\nlinked de.example.com\nlinked subs.example.com\n"}
	d, _ := newDeployer(r, "0.2.0")
	p, files, ruleSets := plan(t, "de")
	require.NoError(t, d.Deploy(t.Context(), p, files, ruleSets))
	require.Equal(t, []string{
		"probe", "provision",
		"copy de.example.com", "copy subs.example.com",
		"apply", "prune",
	}, r.steps, "copied before the engine restarts without access to certbot's")
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
	require.Contains(t, script, "if ! [ -s '/var/lib/princo/certs/subs.example.com/fullchain.pem' ] || ! [ -s '/var/lib/princo/certs/subs.example.com/key.pem' ]; then\n\techo missing 'subs.example.com'\nelif [ -L '/var/lib/princo/certs/subs.example.com/key.pem' ]; then\n\techo linked 'subs.example.com'\nfi")
}

func TestProvision(t *testing.T) {
	r := &fakeRemote{t: t}
	d, _ := newDeployer(r, "0.2.0")
	var script string
	d.Remote = remoteFunc(func(s string) { script = s })
	p, _, _ := plan(t, "de")
	require.NoError(t, d.provision(t.Context(), p))
	require.Contains(t, script, "for p in 'nginx' 'libnginx-mod-stream' 'certbot'; do")
	require.Equal(t, []string{
		"allow 443/tcp comment princo", "allow 80/tcp comment princo", "allow 443/udp comment princo",
	}, runUFW(t, script, ""))
	require.Equal(t, []string{
		"allow 443/tcp comment princo", "allow proto tcp from 0.0.0.0/0 to any port 80 comment princo", "allow 443/udp comment princo",
	}, runUFW(t, script, `22/tcp                     ALLOW       Anywhere
80/tcp (v6)                ALLOW       Anywhere (v6)
`), "the user's IPv6 rule for 80 stays theirs")

	p, _, _ = plan(t, "us")
	require.NoError(t, d.provision(t.Context(), p))
	require.Contains(t, script, "for p in; do")
	require.Equal(t, []string{"allow 443/tcp comment princo"}, runUFW(t, script, ""))
}

func TestCleanup(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"sing-box-1.0.0", "sing-box-1.1.0"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o755))
	}
	p, _, _ := plan(t, "us")
	script, err := execute("cleanup.sh", map[string]any{"Root": root, "Keep": filepath.Join(root, "sing-box-1.1.0"), "Ports": ports(p)})
	require.NoError(t, err)
	require.Equal(t, []string{"--force delete 5", "--force delete 3", "--force delete 2"}, runUFW(t, string(script), `     To                         Action      From
     --                         ------      ----
[ 1] 443/tcp                    ALLOW IN    Anywhere                   # princo
[ 2] 443/udp                    ALLOW IN    Anywhere                   # princo
[ 3] 80/tcp                     ALLOW IN    Anywhere                   # princo
[ 4] 22/tcp                     ALLOW IN    Anywhere
[ 5] 443/udp (v6)               ALLOW IN    Anywhere (v6)              # princo
[ 6] 80/tcp (v6)                ALLOW IN    Anywhere (v6)
`), "the node no longer uses 80 and UDP 443; the user's rules stay")
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "sing-box-1.1.0", entries[0].Name())
}

// runUFW runs script against an active ufw with rules, and returns the
// ufw commands it ran besides status.
func runUFW(t *testing.T, script, rules string) []string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "ufw.log")
	fake := map[string]string{
		"dpkg-query": "echo 'install ok installed'",
		"getent":     "exit 0",
		"ufw":        `if [ "$1" = status ]; then printf 'Status: active\n\n%s' "$RULES"; else echo "$*" >>"$LOG"; fi`,
	}
	for name, body := range fake {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "RULES="+rules, "LOG="+log)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	data, err := os.ReadFile(log)
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
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
	require.ErrorContains(t, d.Deploy(t.Context(), p, files, ruleSets), "there's no xray 26.10.21 for arm64")

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

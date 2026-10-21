//go:build e2e

// Package e2e deploys the fixture fleet's nodes to a real Debian or Ubuntu
// host. PRINCO_E2E_BIN is the princo to run, already installed on the
// host; PRINCO_E2E_HOST the ssh target, root or with passwordless sudo.
// The host is changed for good: give it a throwaway machine.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const fixture = "../testdata/fleet"

type env struct {
	bin, host, config, secrets string
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{bin: os.Getenv("PRINCO_E2E_BIN"), host: os.Getenv("PRINCO_E2E_HOST")}
	if e.bin == "" || e.host == "" {
		t.Fatal("set PRINCO_E2E_BIN and PRINCO_E2E_HOST")
	}
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(fixture, "princo.yaml"))
	require.NoError(t, err)
	e.config = filepath.Join(dir, "princo.yaml")
	require.NoError(t, os.WriteFile(e.config, data, 0o644))

	plain, err := os.ReadFile(filepath.Join(fixture, "secrets.test.yaml"))
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, yaml.Unmarshal(plain, &values))
	e.secrets = filepath.Join(dir, "secrets")
	writeSecrets(t, e.secrets, values)
	return e
}

func writeSecrets(t *testing.T, dir string, values map[string]any) {
	t.Helper()
	for k, v := range values {
		path := filepath.Join(dir, k)
		if m, ok := v.(map[string]any); ok {
			writeSecrets(t, path, m)
			continue
		}
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprint(v)), 0o600))
	}
}

// deploy runs princo deploy and returns its stdout.
func (e *env) deploy(t *testing.T, node string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), e.bin, "--config", e.config, "--secrets-dir", e.secrets,
		"deploy", "--node", node, "--host", e.host)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	t.Logf("deploy %s:\n%s%s", node, stdout.String(), stderr.String())
	if err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// sh runs a script as root on the host and returns its output.
func (e *env) sh(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "ssh", e.host, "sudo -n sh -s")
	cmd.Stdin = strings.NewReader("set -eu\n" + script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s\n%s", script, out)
	return strings.TrimSpace(string(out))
}

// start runs command as a transient unit on the host until the test ends.
func (e *env) start(t *testing.T, unit, command string) {
	t.Helper()
	e.sh(t, "systemd-run --collect --unit="+unit+" "+command+"\nsleep 1")
	t.Cleanup(func() { _ = exec.Command("ssh", e.host, "sudo -n systemctl stop "+unit).Run() })
}

func (e *env) setConfig(t *testing.T, old, new string) {
	t.Helper()
	data, err := os.ReadFile(e.config)
	require.NoError(t, err)
	require.Contains(t, string(data), old)
	require.NoError(t, os.WriteFile(e.config, []byte(strings.Replace(string(data), old, new, 1)), 0o644))
}

// The steps build on each other, in order.
func TestDeploy(t *testing.T) {
	e := setup(t)

	t.Run("fresh", func(t *testing.T) {
		out, err := e.deploy(t, "us")
		require.NoError(t, err)
		require.Contains(t, out, "+ /var/lib/princo/files/sing-box.json\n")
		require.Equal(t, "active", e.sh(t, "systemctl is-active princo.service"))
		require.Contains(t, e.sh(t, "ss -Htln sport = :443"), "LISTEN")
		require.Equal(t, "600", e.sh(t, "stat -c %a /var/lib/princo/applied.json"))
	})

	t.Run("unchanged", func(t *testing.T) {
		out, err := e.deploy(t, "us")
		require.NoError(t, err)
		require.Empty(t, out)
	})

	t.Run("engine stops after restart", func(t *testing.T) {
		e.sh(t, "systemctl stop princo.service")
		e.start(t, "princo-e2e-squatter", "systemd-socket-activate -l 443 cat")
		e.setConfig(t, "short_id: 2b4398e0", "short_id: 2b4398e1")
		_, err := e.deploy(t, "us")
		require.ErrorContains(t, err, "princo.service stopped after it restarted")
		require.ErrorContains(t, err, "the old files are back")
		require.Contains(t, e.sh(t, "cat /var/lib/princo/files/sing-box.json"), "2b4398e0")

		e.sh(t, "systemctl stop princo-e2e-squatter")
		out, err := e.deploy(t, "us")
		require.NoError(t, err)
		require.Equal(t, "~ /var/lib/princo/files/sing-box.json\n", out)
		require.Equal(t, "active", e.sh(t, "systemctl is-active princo.service"))
	})

	t.Run("locked", func(t *testing.T) {
		e.start(t, "princo-e2e-locker", "flock /var/lib/princo/apply.lock sleep 300")
		_, err := e.deploy(t, "us")
		require.ErrorContains(t, err, "another princo host apply is running")
	})

	t.Run("other node refused", func(t *testing.T) {
		_, err := e.deploy(t, "de")
		require.ErrorContains(t, err, "this host runs node us, not de")
	})

	t.Run("multiplexer added", func(t *testing.T) {
		// ACME can't reach a test host: certificates go in by hand.
		e.sh(t, `rm /var/lib/princo/applied.json
for d in de.example.com naive-de.example.com subs.example.com; do
	mkdir -p /var/lib/princo/certs/$d
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
		-keyout /var/lib/princo/certs/$d/key.pem -out /var/lib/princo/certs/$d/fullchain.pem \
		-subj /CN=$d -addext subjectAltName=DNS:$d 2>/dev/null
done`)
		_, err := e.deploy(t, "de")
		require.NoError(t, err)
		require.Equal(t, "active\nactive", e.sh(t, "systemctl is-active princo.service nginx.service"))

		token := e.sh(t, "awk '/^alice /{print $2}' /var/lib/princo/files/tokens.txt")
		curl := "curl -sfk --resolve subs.example.com:443:127.0.0.1 https://subs.example.com/" + token
		require.Contains(t, e.sh(t, curl+"/ | base64 -d"), "vless://")
		require.Contains(t, e.sh(t, curl+" -A 'SFA (sing-box 1.14)'"), `"outbounds"`)
		require.Contains(t, e.sh(t, "echo | openssl s_client -connect 127.0.0.1:443 -servername naive-de.example.com 2>/dev/null | grep ^subject"),
			"naive-de.example.com", "naive behind the multiplexer")
		require.Equal(t, "403", e.sh(t, "curl -sk -o /dev/null -w '%{http_code}' --resolve subs.example.com:443:127.0.0.1 https://subs.example.com/"))

		e.sh(t, `mkdir -p /var/lib/princo/acme/.well-known/acme-challenge
echo token >/var/lib/princo/acme/.well-known/acme-challenge/t`)
		require.Equal(t, "token", e.sh(t, "curl -sf -H 'Host: naive-de.example.com' http://127.0.0.1/.well-known/acme-challenge/t"))
		e.sh(t, "rm -r /var/lib/princo/acme/.well-known")
	})

	t.Run("multiplexer removed", func(t *testing.T) {
		e.sh(t, "rm /var/lib/princo/applied.json")
		_, err := e.deploy(t, "us")
		require.NoError(t, err)
		require.Equal(t, "active", e.sh(t, "systemctl is-active princo.service"))
		require.Contains(t, e.sh(t, "ss -Htlnp sport = :443"), "sing-box", "the engine has TCP 443 back from nginx")
	})

	t.Run("xray", func(t *testing.T) {
		e.sh(t, "rm /var/lib/princo/applied.json")
		// Out of the node itself, to a site on the host.
		e.setConfig(t, "path: /f7Kq2m", "path: /f7Kq2m\n    egress: direct")
		out, err := e.deploy(t, "fi")
		require.NoError(t, err)
		require.Contains(t, out, "+ /var/lib/princo/files/xray.json\n")
		require.Equal(t, "active", e.sh(t, "systemctl is-active princo.service"))
		require.Contains(t, e.sh(t, "ss -Htlnp sport = :443"), "xray")

		e.start(t, "princo-e2e-site", "python3 -m http.server 18080 --bind 127.0.0.1 --directory /var/lib/princo/rules")
		status := "curl -s -o /dev/null -w '%{http_code}' "
		require.Equal(t, "200", e.sh(t, status+"http://127.0.0.1:18080/"))
		reality := map[string]any{
			"serverName":  "www.samsung.com",
			"fingerprint": "chrome",
			"publicKey":   "x1UdIXGj0boXzk96E0ZBwNxdTvF-YwsK4XGVqVhvfFc",
			"shortId":     "3c5409f1",
		}
		for i, c := range []struct {
			name, flow string
			stream     map[string]any
		}{
			{"vision", "xtls-rprx-vision", map[string]any{"network": "raw", "security": "reality", "realitySettings": reality}},
			{"xhttp", "", map[string]any{
				"network": "xhttp", "security": "reality", "realitySettings": reality,
				"xhttpSettings": map[string]any{"path": "/f7Kq2m", "mode": "auto"},
			}},
		} {
			port := 10801 + i
			client, err := json.Marshal(map[string]any{
				"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks"}},
				"outbounds": []any{map[string]any{
					"protocol": "vless",
					"settings": map[string]any{
						"address": "127.0.0.1", "port": 443, "encryption": "none", "flow": c.flow,
						"id": "dbc5aca6-f0dd-416d-b30f-813754d72f99", // alice
					},
					"streamSettings": c.stream,
				}},
			})
			require.NoError(t, err)
			config := "/tmp/princo-e2e-" + c.name + ".json"
			e.sh(t, "cat >"+config+" <<'EOF'\n"+string(client)+"\nEOF")
			e.start(t, "princo-e2e-"+c.name, "/usr/local/lib/princo/xray-26.10.21/xray run -c "+config)
			proxy := fmt.Sprintf("--socks5-hostname 127.0.0.1:%d ", port)
			require.Equal(t, "204", e.sh(t, status+proxy+"http://www.gstatic.com/generate_204"),
				"alice gets through over %s", c.name)
			require.Equal(t, "000", e.sh(t, status+proxy+"http://127.0.0.1:18080/ || true"),
				"the node's loopback is out of reach over %s", c.name)
		}
	})
}

package cli

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/secrets"
)

// fakeSSH puts an ssh on PATH that logs its calls in dir/calls, keeps the
// stdin of princo host apply in dir/stdin, and answers like a host with
// princo 0.1.1 would.
func fakeSSH(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	script := `#!/bin/sh
echo "$*" >>` + dir + `/calls
for a; do last=$a; done
case "$last" in
*"sh -s") script=$(cat) ;;
*) script=$last ;;
esac
case "$script" in
*"dpkg --print-architecture"*) printf 'arch amd64\nprinco 0.1.1\n' ;;
*"princo host apply"*)
	cat >` + dir + `/stdin
	echo '+ /etc/systemd/system/princo.service'
	;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func sshCalls(t *testing.T, dir string) string {
	t.Helper()
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	require.NoError(t, err)
	return string(calls)
}

func ruleSetDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"geoip-ru.srs", "geosite-category-ru.srs"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("SRS "+f), 0o644))
	}
	return dir
}

func runDeploy(t *testing.T, args ...string) (string, error) {
	t.Helper()
	configPath, keyPath := fixtureDir(t)
	var stdout bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetArgs(append([]string{"--config", configPath, "--key", keyPath, "deploy", "--rule-sets", ruleSetDir(t)}, args...))
	err := cmd.Execute()
	return stdout.String(), err
}

func TestDeploy_DryRun(t *testing.T) {
	ssh := fakeSSH(t)
	out, err := runDeploy(t, "--node", "de", "--dry-run")
	require.NoError(t, err)
	require.Equal(t, "+ /etc/systemd/system/princo.service\n", out)

	calls := sshCalls(t, ssh)
	require.Contains(t, calls, "-f -N root@de.example.com\n", "the node's ssh: from princo.yaml")
	require.Contains(t, calls, `set -- sudo -n; fi; exec "$@" sh -c 'princo host apply --check'`)
	require.Contains(t, calls, "-O exit root@de.example.com\n")

	stdin, err := os.ReadFile(filepath.Join(ssh, "stdin"))
	require.NoError(t, err)
	var b bundle.Bundle
	require.NoError(t, json.Unmarshal(stdin, &b))
	require.Equal(t, "de", b.Node)
	var config []byte
	for _, f := range b.Files {
		if f.Path == "/var/lib/princo/files/sing-box.json" {
			config = f.Data
		}
	}
	require.Contains(t, string(config), `"uuid"`)
	require.Empty(t, secrets.Placeholders(config), "secrets are resolved before they leave")
}

func TestDeploy_Host(t *testing.T) {
	ssh := fakeSSH(t)
	_, err := runDeploy(t, "--node", "us", "--host", "admin@10.0.0.1", "--dry-run")
	require.NoError(t, err)
	require.Contains(t, sshCalls(t, ssh), "-f -N admin@10.0.0.1\n")
}

func TestDeploy_Flags(t *testing.T) {
	fakeSSH(t)
	_, err := runDeploy(t, "--dry-run")
	require.ErrorContains(t, err, "--node is required")
	_, err = runDeploy(t, "--node", "de", "--host", "-oProxyCommand=x", "--dry-run")
	require.ErrorContains(t, err, `bad ssh target "-oProxyCommand=x"`)
}

package cli

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/secrets"
)

// fakeSSH puts an ssh on PATH that records its arguments and stdin in dir
// and prints what princo host apply --check would.
func fakeSSH(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + dir + "/args\ncat > " + dir + "/stdin\necho '+ /etc/systemd/system/princo.service'\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
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

	args, err := os.ReadFile(filepath.Join(ssh, "args"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(string(args), "\n"), "\n")
	require.Equal(t, "root@de.example.com", lines[0], "the node's ssh: from princo.yaml")
	require.Contains(t, lines[1], "sudo -n princo host apply --check")

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
	args, err := os.ReadFile(filepath.Join(ssh, "args"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(args), "admin@10.0.0.1\n"))
}

func TestDeploy_Flags(t *testing.T) {
	fakeSSH(t)
	_, err := runDeploy(t, "--dry-run")
	require.ErrorContains(t, err, "--node is required")
	_, err = runDeploy(t, "--node", "de")
	require.ErrorContains(t, err, "only --dry-run works yet")
	_, err = runDeploy(t, "--node", "de", "--host", "-oProxyCommand=x", "--dry-run")
	require.ErrorContains(t, err, `bad ssh target "-oProxyCommand=x"`)
}

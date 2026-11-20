package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// publishedConfig is the fixture with its client profiles' rule sets
// published at url.
func publishedConfig(t *testing.T, url string) (configPath, keyPath string) {
	t.Helper()
	configPath, keyPath = fixtureDir(t)
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	const domains = "  domains: [subs.example.com, subs.example.org]\n"
	require.Contains(t, string(data), domains)
	data = []byte(strings.Replace(string(data), domains, domains+"  rule_sets: { url: \""+url+"\" }\n", 1))
	require.NoError(t, os.WriteFile(configPath, data, 0o644))
	return configPath, keyPath
}

func runRuleSets(t *testing.T, configPath string, args ...string) error {
	t.Helper()
	cmd := NewRootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"--config", configPath, "rule-sets"}, args...))
	return cmd.Execute()
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// A node keeps its engine's rule sets and, serving the site, the client
// profiles'; published elsewhere, those are built with --client alone.
func TestRuleSets_Client(t *testing.T) {
	configPath, _ := fixtureDir(t)
	client := []string{"geoip-ru.srs", "geosite-category-ru.srs"}

	out := t.TempDir()
	require.NoError(t, runRuleSets(t, configPath, "--node", "fi", "--from", ruleSetDir(t), "--out", out))
	require.Equal(t, []string{"geoip.dat", "geosite.dat"}, names(t, out), "fi serves no site")
	require.ErrorContains(t, runRuleSets(t, configPath, "--node", "fi", "--client", "--from", ruleSetDir(t), "--out", out),
		"node fi doesn't serve the subscription")
	require.ErrorContains(t, runRuleSets(t, configPath, "--node", "de", "--check"), "subscription.rule_sets.url isn't set")
	require.ErrorContains(t, runRuleSets(t, configPath, "--node", "de", "--check", "--out", out), "--check builds nothing")
	require.ErrorContains(t, runRuleSets(t, configPath, "--node", "de"), "--out is required")

	configPath, _ = publishedConfig(t, "https://127.0.0.1:1/princo")
	out = t.TempDir()
	require.NoError(t, runRuleSets(t, configPath, "--node", "de", "--client", "--from", ruleSetDir(t), "--out", out))
	require.Equal(t, client, names(t, out))
	require.ErrorContains(t, runRuleSets(t, configPath, "--node", "de", "--check"), "rule set geoip-ru.srs: ")
}

// The node serving the subscription isn't touched until the address the
// profiles name serves their rule sets.
func TestDeploy_UnpublishedRuleSets(t *testing.T) {
	ssh := fakeSSH(t)
	configPath, keyPath := publishedConfig(t, "https://127.0.0.1:1/princo")
	cmd := NewRootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--config", configPath, "--key", keyPath, "deploy", "--rule-sets", ruleSetDir(t), "--node", "de"})
	require.ErrorContains(t, cmd.Execute(), "rule set geoip-ru.srs: ")
	require.NoFileExists(t, filepath.Join(ssh, "calls"))
}

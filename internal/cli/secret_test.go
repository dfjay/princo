package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/secrets"
)

func newSecretFixture(t *testing.T) (configPath, keyPath, recipientsPath string) {
	t.Helper()
	tmp := t.TempDir()
	configPath = filepath.Join(tmp, "princo.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("princo: v1\n"), 0644))

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyPath = filepath.Join(tmp, "key.txt")
	require.NoError(t, os.WriteFile(keyPath, []byte(id.String()+"\n"), 0600))

	recipientsPath = filepath.Join(tmp, "recipients")
	require.NoError(t, os.WriteFile(recipientsPath, []byte(id.Recipient().String()+"\n"), 0644))
	require.NoError(t, secrets.Save(filepath.Join(tmp, "secrets.age"), recipientsPath, map[string]any{}))
	return
}

func TestSecret_SetThenGet(t *testing.T) {
	configPath, keyPath, _ := newSecretFixture(t)

	cmd := NewRootCommand()
	cmd.SetIn(strings.NewReader("super-secret-value\n"))
	cmd.SetArgs([]string{
		"--config", configPath, "--key", keyPath,
		"secret", "set", "uuids/alice",
	})
	require.NoError(t, cmd.Execute())

	var stdout bytes.Buffer
	cmd2 := NewRootCommand()
	cmd2.SetOut(&stdout)
	cmd2.SetArgs([]string{
		"--config", configPath, "--key", keyPath,
		"secret", "get", "uuids/alice",
	})
	require.NoError(t, cmd2.Execute())
	require.Equal(t, "super-secret-value\n", stdout.String())
}

func TestSecret_SetCreatesFile(t *testing.T) {
	configPath, keyPath, _ := newSecretFixture(t)
	require.NoError(t, os.Remove(filepath.Join(filepath.Dir(configPath), "secrets.age")))

	cmd := NewRootCommand()
	cmd.SetIn(strings.NewReader("first\n"))
	cmd.SetArgs([]string{"--config", configPath, "--key", keyPath, "secret", "set", "users/alice"})
	require.NoError(t, cmd.Execute())

	var stdout bytes.Buffer
	cmd = NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--config", configPath, "--key", keyPath, "secret", "get", "users/alice"})
	require.NoError(t, cmd.Execute())
	require.Equal(t, "first\n", stdout.String())
}

func TestSecret_List(t *testing.T) {
	configPath, keyPath, _ := newSecretFixture(t)
	require.NoError(t, os.WriteFile(configPath, []byte(`princo: v1
nodes:
  fr: { address: fr.example.com, reality: { server_name: www.example.com, short_id: "01" } }
users:
  alice: {}
  bob: {}
secrets:
  users/*: age:users.age
`), 0o644))
	list := func(args ...string) (string, error) {
		t.Helper()
		var stdout bytes.Buffer
		cmd := NewRootCommand()
		cmd.SetOut(&stdout)
		cmd.SetIn(strings.NewReader("uuid-a\n"))
		cmd.SetArgs(append([]string{"--config", configPath, "--key", keyPath, "secret"}, args...))
		err := cmd.Execute()
		return stdout.String(), err
	}

	// Without --check, nothing is decrypted: the key may as well be gone.
	require.NoError(t, os.Rename(keyPath, keyPath+".away"))
	out, err := list("list")
	require.NoError(t, err)
	require.Equal(t, []string{"nodes/fr/reality", "users/alice", "users/bob"}, listedPaths(out))
	require.Contains(t, out, "age:users.age#alice")
	require.Contains(t, out, "age:secrets.age#nodes/fr/reality")
	require.NotContains(t, out, "VALUE")
	require.NoError(t, os.Rename(keyPath+".away", keyPath))

	_, err = list("set", "users/alice")
	require.NoError(t, err)
	out, err = list("list", "--check")
	require.ErrorContains(t, err, "2 secrets have no value: nodes/fr/reality, users/bob")
	require.Regexp(t, `users/alice\s+age:users.age#alice\s+\S+princo.yaml\s+set`, out)
	require.Regexp(t, `users/bob\s+.*missing`, out)
}

// listedPaths returns the paths secret list printed, in order.
func listedPaths(out string) []string {
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
		paths = append(paths, strings.Fields(line)[0])
	}
	return paths
}

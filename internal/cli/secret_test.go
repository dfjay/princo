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
	configPath, keyPath, recPath := newSecretFixture(t)
	require.NoError(t, secrets.Save(
		filepath.Join(filepath.Dir(configPath), "secrets.age"),
		recPath,
		map[string]any{"uuids": map[string]any{"alice": "a", "bob": "b"}},
	))

	var stdout bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{
		"--config", configPath, "--key", keyPath,
		"secret", "list",
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, stdout.String(), "uuids/alice")
	require.Contains(t, stdout.String(), "uuids/bob")
}

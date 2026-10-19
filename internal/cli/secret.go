package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/secrets"
)

func newSecretCommand(global *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage encrypted secrets",
	}
	cmd.AddCommand(newSecretGetCommand(global))
	cmd.AddCommand(newSecretSetCommand(global))
	cmd.AddCommand(newSecretListCommand(global))
	return cmd
}

func newSecretGetCommand(global *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <path>",
		Short: "Print a secret value, wherever princo.yaml's secrets: block maps it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(global)
			if err != nil {
				return err
			}
			resolver, err := newResolver(global, cfg)
			if err != nil {
				return err
			}
			v, err := resolver.Get(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), v)
			return err
		},
	}
}

func newSecretSetCommand(global *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <path>",
		Short: "Set a secret value (reads from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, recipientsPath, err := openSecretStore(global)
			if err != nil {
				return err
			}
			scanner := bufio.NewScanner(cmd.InOrStdin())
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
				return fmt.Errorf("no value on stdin")
			}
			if err := store.Set(args[0], scanner.Text()); err != nil {
				return err
			}
			return secrets.Save(secretsPath(global.ConfigPath), recipientsPath, store.Values())
		},
	}
}

func newSecretListCommand(global *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all secret paths (values not shown)",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, _, err := openSecretStore(global)
			if err != nil {
				return err
			}
			paths := store.List()
			sort.Strings(paths)
			for _, p := range paths {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), p); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// openSecretStore loads the secrets next to the config file and returns
// (store, path-to-recipients-file, error). Recipients live in `.princo/recipients`
// or `recipients` next to the config.
func openSecretStore(global *globalFlags) (*secrets.Store, string, error) {
	path := secretsPath(global.ConfigPath)
	var store *secrets.Store
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		// The first `secret set` creates it.
		store = secrets.NewStore(map[string]any{})
	} else if store, err = secrets.Open(path, identityPath(global)); err != nil {
		return nil, "", err
	}
	dir := filepath.Dir(global.ConfigPath)
	candidates := []string{
		filepath.Join(dir, ".princo", "recipients"),
		filepath.Join(dir, "recipients"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return store, p, nil
		}
	}
	return nil, "", fmt.Errorf("no recipients file found (tried %v)", candidates)
}

// secretsPath converts /path/to/princo.yaml → /path/to/secrets.age.
func secretsPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), secrets.DefaultFile)
}

// identityPath is the age identity for age-encrypted secrets.
func identityPath(global *globalFlags) string {
	if global.KeyPath != "" {
		return global.KeyPath
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "princo", "key.txt")
}

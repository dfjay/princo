package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dfjay/princo/internal/fleet"
)

func newSecretCommand(global *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage encrypted secrets",
	}
	cmd.AddCommand(newSecretGetCommand(global))
	cmd.AddCommand(newSecretSetCommand(global))
	cmd.AddCommand(newSecretGenCommand(global))
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
		Short: "Set a secret value, wherever princo.yaml's secrets: block maps it",
		Long: `Set a secret value: typed without echo, or the first line of stdin. It
goes where princo.yaml's secrets: block maps the path, sops files included,
or to secrets.age next to princo.yaml.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(global)
			if err != nil {
				return err
			}
			resolver, err := newResolver(global, cfg)
			if err != nil {
				return err
			}
			value, err := readValue(cmd, args[0])
			if err != nil {
				return err
			}
			return resolver.Set(args[0], value)
		},
	}
}

// readValue reads a secret's value: from the terminal without echoing it,
// or the first line of piped stdin.
func readValue(cmd *cobra.Command, path string) (string, error) {
	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s: ", path); err != nil {
			return "", err
		}
		value, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(cmd.ErrOrStderr()) // end the prompt's line
		if err != nil {
			return "", fmt.Errorf("read terminal: %w", err)
		}
		if len(value) == 0 {
			return "", fmt.Errorf("no value entered")
		}
		return string(value), nil
	}
	scanner := bufio.NewScanner(cmd.InOrStdin())
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return "", fmt.Errorf("no value on stdin")
	}
	return scanner.Text(), nil
}

func newSecretListCommand(global *globalFlags) *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the secrets the config uses and where each is stored",
		Long: `List every secret path the config uses, where its secrets: block stores
it, and the config file that says so; values are never shown. Without
--check nothing is decrypted. With --check, princo also decrypts the
stores and fails when a secret has no value.`,
		Example: `  princo secret list
  princo secret list --check  # which ones secret gen or secret set still has to fill in`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(global)
			if err != nil {
				return err
			}
			resolver, err := newResolver(global, cfg)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			header := "PATH\tLOCATION\tCONFIG"
			if check {
				header += "\tVALUE"
			}
			_, _ = fmt.Fprintln(w, header) // Flush reports errors
			var missing []string
			seen := map[string]bool{}
			for _, u := range fleet.Secrets(cfg) {
				if seen[u.Path] {
					continue
				}
				seen[u.Path] = true
				location, file := resolver.Where(u.Path)
				line := u.Path + "\t" + location + "\t" + global.ConfigPaths[file]
				if check {
					has, err := resolver.Has(u.Path)
					if err != nil {
						return err
					}
					if has {
						line += "\tset"
					} else {
						line += "\tmissing"
						missing = append(missing, u.Path)
					}
				}
				_, _ = fmt.Fprintln(w, line)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if len(missing) > 0 {
				return fmt.Errorf("%d secrets have no value: %s", len(missing), strings.Join(missing, ", "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Decrypt the stores and fail when a secret has no value")
	return cmd
}

// recipientsPath is the recipients file next to the config:
// `.princo/recipients` if it exists, else `recipients`.
func recipientsPath(global *globalFlags) string {
	dir := filepath.Dir(global.configPath())
	if p := filepath.Join(dir, ".princo", "recipients"); fileExists(p) {
		return p
	}
	return filepath.Join(dir, "recipients")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// identityPath is the age identity for age-encrypted secrets.
func identityPath(global *globalFlags) string {
	if global.KeyPath != "" {
		return global.KeyPath
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "princo", "key.txt")
}

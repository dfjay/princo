package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/engine"
	_ "github.com/dfjay/princo/internal/engine/singbox"
	_ "github.com/dfjay/princo/internal/engine/xray"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
	"github.com/dfjay/princo/internal/subscription"
)

func newRenderCommand(global *globalFlags) *cobra.Command {
	var nodeName, userName, outDir, platform string
	var uris, links bool
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Print a node's engine config, or a user's client profile or share links",
		Example: `  princo render --node fr        # server config of node fr
  princo render --user alice     # alice's client profile
  princo render --user router --platform linux  # for sing-box as a Linux service
  princo render --user alice --uris
  princo render --user alice --links  # alice's subscription links
  princo render --node fr --out /run/princo  # every file node fr runs from`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if (nodeName == "") == (userName == "") {
				return fmt.Errorf("pass exactly one of --node or --user")
			}
			if (uris || links) && userName == "" {
				return fmt.Errorf("--uris and --links need --user")
			}
			if uris && links {
				return fmt.Errorf("pass at most one of --uris or --links")
			}
			if outDir != "" && nodeName == "" {
				return fmt.Errorf("--out needs --node")
			}
			client, err := engine.Lookup(engine.ClientEngine)
			if err != nil {
				return err
			}
			p := engine.Platform(platform)
			switch {
			case p != engine.AnyPlatform && (userName == "" || uris || links):
				return fmt.Errorf("--platform needs --user, without --uris or --links")
			case p != engine.AnyPlatform && !slices.Contains(client.ClientPlatforms(), p):
				return fmt.Errorf("--platform %s: %s has profiles for %s", p, client.Name(), joinPlatforms(client.ClientPlatforms()))
			}
			f, err := loadFleet(global)
			if err != nil {
				return err
			}
			if outDir != "" {
				files, err := host.Files(f, nodeName)
				if err != nil {
					return err
				}
				for _, data := range files {
					if err := checkSecrets(global, data); err != nil {
						return err
					}
				}
				return writeDir(outDir, files)
			}

			var out []byte
			switch {
			case nodeName != "":
				n, ok := f.Node(nodeName)
				if !ok {
					return fmt.Errorf("no node named %q", nodeName)
				}
				e, err := engine.Lookup(n.Engine)
				if err != nil {
					return err
				}
				if out, err = e.RenderServer(f, nodeName); err != nil {
					return err
				}
			case uris:
				u, ok := f.User(userName)
				if !ok {
					return fmt.Errorf("no user named %q", userName)
				}
				out = []byte(strings.Join(subscription.URIs(u), "\n"))
			case links:
				u, ok := f.User(userName)
				if !ok {
					return fmt.Errorf("no user named %q", userName)
				}
				// The links hash the UUID, which hides a placeholder for it.
				if err := checkSecrets(global, []byte(u.UUID)); err != nil {
					return err
				}
				l, ok := subscription.UserLinks(f, u)
				if !ok {
					return fmt.Errorf("princo.yaml has no subscription")
				}
				out = fmt.Appendf(nil, "QR page:   %s\nUniversal: %s\nsing-box:  %s", l.QR, l.Universal, l.SingBox)
				for _, p := range client.ClientPlatforms() {
					out = fmt.Appendf(out, "\n%-10s %s", string(p)+":", l.Profile(client.Name(), p))
				}
			default:
				if out, err = client.RenderClient(f, userName, p); err != nil {
					return err
				}
			}
			if err := checkSecrets(global, out); err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node whose server config to render")
	cmd.Flags().StringVar(&userName, "user", "", "User whose client profile to render")
	cmd.Flags().BoolVar(&uris, "uris", false, "With --user: print share links instead of the profile")
	cmd.Flags().BoolVar(&links, "links", false, "With --user: print the user's subscription links instead of the profile")
	var platforms []engine.Platform
	if e, err := engine.Lookup(engine.ClientEngine); err == nil {
		platforms = e.ClientPlatforms()
	}
	cmd.Flags().StringVar(&platform, "platform", "", "With --user: the platform the profile runs on, for what only it supports ("+joinPlatforms(platforms)+"); the apps' profile when unset")
	cmd.Flags().StringVar(&outDir, "out", "", "With --node: write the config and, on the subscription node, the site into this directory, replacing it")
	return cmd
}

func joinPlatforms(ps []engine.Platform) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = string(p)
	}
	return strings.Join(names, ", ")
}

// loadFleet reads princo.yaml and resolves its secrets.
func loadFleet(global *globalFlags) (*fleet.Fleet, error) {
	cfg, err := loadConfig(global)
	if err != nil {
		return nil, err
	}
	if global.SecretsDir != "" {
		// A host holds only the secrets its own files need; checkSecrets
		// catches the output that needed one more.
		return fleet.Build(cfg, secrets.OrPlaceholder{Getter: secrets.Dir(global.SecretsDir)})
	}
	resolver, err := newResolver(global, cfg)
	if err != nil {
		return nil, err
	}
	return fleet.Build(cfg, resolver)
}

// checkSecrets fails when rendered data still holds placeholders for
// secrets missing from --secrets-dir.
func checkSecrets(global *globalFlags, data []byte) error {
	missing := secrets.Placeholders(data)
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("secrets missing from %s: %s", global.SecretsDir, strings.Join(missing, ", "))
}

// writeDir replaces dir with files: they are written to a sibling first
// and swapped in, so readers never see a half-written dir.
func writeDir(dir string, files map[string][]byte) error {
	dir = filepath.Clean(dir)
	stage, err := os.MkdirTemp(filepath.Dir(dir), "."+filepath.Base(dir)+".new-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }() // gone after a successful swap
	if err := os.Chmod(stage, 0o750); err != nil {
		return err
	}
	for name, data := range files {
		path := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0o640); err != nil {
			return err
		}
	}
	old := stage + ".old"
	if err := os.Rename(dir, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, dir); err != nil {
		return err
	}
	return os.RemoveAll(old)
}

func loadConfig(global *globalFlags) (*config.Config, error) {
	files, err := readConfigFiles(global)
	if err != nil {
		return nil, err
	}
	return files.config()
}

// newResolver looks secrets up as the config's secrets: block says.
func newResolver(global *globalFlags, cfg *config.Config) (*secrets.Resolver, error) {
	dirs := make([]string, len(global.ConfigPaths))
	for i, p := range global.ConfigPaths {
		dirs[i] = filepath.Dir(p)
	}
	r, err := secrets.NewResolver(dirs, identityPath(global), cfg.SecretMappings())
	if err != nil {
		return nil, err
	}
	r.Recipients = recipientsPath(global)
	return r, nil
}

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/engine"
	_ "github.com/dfjay/princo/internal/engine/singbox"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/secrets"
	"github.com/dfjay/princo/internal/subscription"
)

func newRenderCommand(global *globalFlags) *cobra.Command {
	var nodeName, userName string
	var uris bool
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Print a node's engine config, or a user's client profile or share links",
		Example: `  princo render --node fr        # server config of node fr
  princo render --user alice     # alice's client profile
  princo render --user alice --uris`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if (nodeName == "") == (userName == "") {
				return fmt.Errorf("pass exactly one of --node or --user")
			}
			if uris && userName == "" {
				return fmt.Errorf("--uris needs --user")
			}
			f, err := loadFleet(global)
			if err != nil {
				return err
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
			default:
				// Client profiles are sing-box for every engine: that's what the apps speak.
				e, err := engine.Lookup("sing-box")
				if err != nil {
					return err
				}
				if out, err = e.RenderClient(f, userName); err != nil {
					return err
				}
			}
			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node whose server config to render")
	cmd.Flags().StringVar(&userName, "user", "", "User whose client profile to render")
	cmd.Flags().BoolVar(&uris, "uris", false, "With --user: print share links instead of the profile")
	return cmd
}

// loadFleet reads princo.yaml and resolves its secrets.
func loadFleet(global *globalFlags) (*fleet.Fleet, error) {
	cfg, err := loadConfig(global)
	if err != nil {
		return nil, err
	}
	resolver, err := newResolver(global, cfg)
	if err != nil {
		return nil, err
	}
	return fleet.Build(cfg, resolver)
}

func loadConfig(global *globalFlags) (*config.Config, error) {
	data, err := os.ReadFile(global.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return config.Parse(data)
}

// newResolver looks secrets up as princo.yaml's secrets: block says, with paths relative to the config file.
func newResolver(global *globalFlags, cfg *config.Config) (*secrets.Resolver, error) {
	return secrets.NewResolver(filepath.Dir(global.ConfigPath), identityPath(global), cfg.SecretMappings())
}

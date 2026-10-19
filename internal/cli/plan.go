package cli

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

func newPlanCommand(global *globalFlags) *cobra.Command {
	var nodeName string
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Print, as JSON, what a deploy sets up around a node's rendered files",
		Long: `Print what a deploy sets up around a node's rendered files: open ports,
the SNI multiplexer, certificates, rule sets and the secrets rendering reads,
with where each is stored. No secret is decrypted; the NixOS module builds
the host from this.`,
		Example: `  princo plan --node fr`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeName == "" {
				return fmt.Errorf("--node is required")
			}
			cfg, err := loadConfig(global)
			if err != nil {
				return err
			}
			resolver, err := newResolver(global, cfg)
			if err != nil {
				return err
			}
			f, err := fleet.Build(cfg, secrets.AllPlaceholders{})
			if err != nil {
				return err
			}
			p, err := host.NewPlan(f, nodeName, resolver.Locate)
			if err != nil {
				return err
			}
			out, err := json.Marshal(p, jsontext.WithIndent("  "))
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node to plan")
	return cmd
}

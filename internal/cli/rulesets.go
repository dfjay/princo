package cli

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/deploy"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

func newRuleSetsCommand(global *globalFlags) *cobra.Command {
	var nodeName, outDir, fromDir string
	cmd := &cobra.Command{
		Use:   "rule-sets",
		Short: "Build a node's rule sets from the fleet's rule data",
		Long: `Build the rule sets a node's plan lists from the fleet's rule_data: those
its engine loads and, on the node serving the subscription, those client
profiles get from the site. They are written to --out, as princo deploy
installs them in /var/lib/princo/rules.

The data is downloaded unless --from names a directory holding it:
geoip.dat or geoip.mmdb, and geosite.dat. No secret is decrypted; the
NixOS module builds the node's rule sets with this.`,
		Example: `  princo rule-sets --node fr --out rules
  princo rule-sets --node fr --out rules --from data`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeName == "" || outDir == "" {
				return fmt.Errorf("--node and --out are required")
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
			files, err := host.Files(f, nodeName)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 5 * time.Minute}
			ruleSets, err := deploy.RuleSets(cmd.Context(), client, fromDir, f.RuleData, p.AllRuleSets(), files[p.Config])
			if err != nil {
				return err
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			for _, name := range slices.Sorted(maps.Keys(ruleSets)) {
				if err := os.WriteFile(filepath.Join(outDir, name), ruleSets[name], 0o644); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node whose rule sets to build")
	cmd.Flags().StringVar(&outDir, "out", "", "Directory to write them to")
	cmd.Flags().StringVar(&fromDir, "from", "", "Directory holding the rule data, instead of downloading it")
	return cmd
}

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
	var clientOnly, check bool
	cmd := &cobra.Command{
		Use:   "rule-sets",
		Short: "Build a node's rule sets from the fleet's rule data",
		Long: `Build the rule sets a node keeps from the fleet's rule_data: those its
engine loads and, on the node serving the subscription, those client
profiles get from the site. They are written to --out, as princo deploy
installs them in /var/lib/princo/rules.

With --client, build the rule sets the client profiles fetch instead,
whoever serves them: the files to publish under
subscription.rule_sets.url, each by its name, before the node serving
the subscription is deployed. --check builds nothing and tells whether
that address serves each of them.

The data is downloaded unless --from names a directory holding it:
geoip.dat or geoip.mmdb, and geosite.dat. No secret is decrypted; the
NixOS module builds the node's rule sets with this.`,
		Example: `  princo rule-sets --node fr --out rules
  princo rule-sets --node fr --out rules --from data
  princo rule-sets --node fr --client --out public
  princo rule-sets --node fr --check`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case nodeName == "":
				return fmt.Errorf("--node is required")
			case check && (outDir != "" || fromDir != "" || clientOnly):
				return fmt.Errorf("--check builds nothing: it goes without --out, --from and --client")
			case !check && outDir == "":
				return fmt.Errorf("--out is required")
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
			p, err := host.NewPlan(f, nodeName, resolver.Where)
			if err != nil {
				return err
			}
			files, err := host.Files(f, nodeName)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 5 * time.Minute}
			names := p.HostRuleSets()
			if clientOnly || check {
				if p.Subscription == nil {
					return fmt.Errorf("node %s doesn't serve the subscription, so it has no client profiles", nodeName)
				}
				names = p.Subscription.RuleSets.Files
			}
			if check {
				url := p.Subscription.RuleSets.URL
				if url == "" {
					return fmt.Errorf("subscription.rule_sets.url isn't set: node %s serves the client profiles' rule sets itself", nodeName)
				}
				return deploy.Published(cmd.Context(), client, url, names)
			}
			ruleSets, err := deploy.RuleSets(cmd.Context(), client, fromDir, f.RuleData, names, files[p.Config])
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
	cmd.Flags().BoolVar(&clientOnly, "client", false, "Build the rule sets the client profiles fetch, to publish them")
	cmd.Flags().BoolVar(&check, "check", false, "Check that subscription.rule_sets.url serves the client profiles' rule sets")
	return cmd
}

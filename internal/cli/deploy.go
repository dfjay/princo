package cli

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/deploy"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

func newDeployCommand(global *globalFlags) *cobra.Command {
	var nodeName, target, ruleSetDir string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy a node to its Debian or Ubuntu host over SSH",
		Long: `Build the bundle a node's host runs from — its rendered files, rule sets,
a systemd unit for the engine, and nginx for the SNI multiplexer and the
subscription site — and apply it on the host with princo host apply,
over the system ssh. The host needs princo of the same bundle format.

Rule sets are downloaded from the engine's upstream unless --rule-sets
names a directory holding them.`,
		Example: `  princo deploy --node fr --dry-run
  princo deploy --node fr --host admin@fr.example.com --dry-run`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeName == "" {
				return fmt.Errorf("--node is required")
			}
			if !dryRun {
				return fmt.Errorf("only --dry-run works yet")
			}
			cfg, err := loadConfig(global)
			if err != nil {
				return err
			}
			resolver, err := newResolver(global, cfg)
			if err != nil {
				return err
			}
			placeholders, err := fleet.Build(cfg, secrets.AllPlaceholders{})
			if err != nil {
				return err
			}
			p, err := host.NewPlan(placeholders, nodeName, resolver.Locate)
			if err != nil {
				return err
			}
			if target == "" {
				n, _ := placeholders.Node(nodeName)
				if target = n.SSH; target == "" {
					return fmt.Errorf("node %s has no ssh: in princo.yaml; pass --host", nodeName)
				}
			}

			f, err := loadFleet(global)
			if err != nil {
				return err
			}
			files, err := host.Files(f, nodeName)
			if err != nil {
				return err
			}
			for _, data := range files {
				if err := checkSecrets(global, data); err != nil {
					return err
				}
			}
			var ruleSets map[string][]byte
			if ruleSetDir != "" {
				ruleSets, err = deploy.ReadRuleSets(ruleSetDir, p.Engine, p.RuleSets)
			} else {
				ruleSets, err = deploy.FetchRuleSets(cmd.Context(), &http.Client{Timeout: time.Minute}, p.Engine, p.RuleSets)
			}
			if err != nil {
				return err
			}
			b, err := deploy.Build(p, files, ruleSets)
			if err != nil {
				return err
			}
			data, err := json.Marshal(b)
			if err != nil {
				return err
			}
			ssh := deploy.SSH{Target: target, Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr()}
			return ssh.AsRoot(cmd.Context(), bytes.NewReader(data), "princo host apply --check")
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node to deploy")
	cmd.Flags().StringVar(&target, "host", "", "SSH target, user@host (default: the node's ssh: in princo.yaml)")
	cmd.Flags().StringVar(&ruleSetDir, "rule-sets", "", "Directory holding the node's rule sets, instead of downloading them")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would change on the host, and change nothing")
	return cmd
}

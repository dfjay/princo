package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/deploy"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
	"github.com/dfjay/princo/internal/version"
)

func newDeployCommand(global *globalFlags) *cobra.Command {
	var nodeName, target, ruleSetDir, debPath string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy a node to its Debian or Ubuntu host over SSH",
		Long: `Deploy a node to its Debian or Ubuntu host over the system ssh, as root
or through sudo -n: install the engine, nginx and certbot, and princo of
this version, verified with cosign (or --princo-deb); issue the
certificates the host lacks; then apply the node's bundle with princo
host apply: its rendered files, rule sets, a systemd unit for the
engine, and nginx for the SNI multiplexer and the subscription site.

Rule sets are downloaded from the engine's upstream unless --rule-sets
names a directory holding them.`,
		Example: `  princo deploy --node fr
  princo deploy --node fr --dry-run
  princo deploy --node fr --host admin@fr.example.com`,
		Args: cobra.NoArgs,
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
			client := &http.Client{Timeout: time.Minute}
			ruleSets, err := deploy.RuleSets(cmd.Context(), client, ruleSetDir, p.Engine, p.RuleSets)
			if err != nil {
				return err
			}
			d := &deploy.Deployer{
				Out:     cmd.OutOrStdout(),
				Log:     cmd.ErrOrStderr(),
				Version: version.String(),
				Release: func(ctx context.Context, v, arch string) ([]byte, error) {
					return deploy.ReleaseDeb(ctx, client, deploy.ReleaseURL, v, arch)
				},
			}
			if debPath != "" {
				if d.Deb, err = os.ReadFile(debPath); err != nil {
					return err
				}
			}
			ssh := &deploy.SSH{Target: target, Stderr: cmd.ErrOrStderr()}
			if err := ssh.Open(cmd.Context()); err != nil {
				return err
			}
			defer func() { _ = ssh.Close() }()
			d.Remote = ssh
			if dryRun {
				return d.Check(cmd.Context(), p, files, ruleSets)
			}
			return d.Deploy(cmd.Context(), p, files, ruleSets)
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node to deploy")
	cmd.Flags().StringVar(&target, "host", "", "SSH target, user@host (default: the node's ssh: in princo.yaml)")
	cmd.Flags().StringVar(&ruleSetDir, "rule-sets", "", "Directory holding the node's rule sets, instead of downloading them")
	cmd.Flags().StringVar(&debPath, "princo-deb", "", "princo .deb to install on the host, instead of this version's release")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would change in the host's files, and change nothing; the host must have princo")
	return cmd
}

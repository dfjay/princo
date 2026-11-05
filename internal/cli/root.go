package cli

import (
	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/version"
)

// Flags shared by every command that loads config + secrets.
type globalFlags struct {
	// ConfigPaths merge in order; new entries, the default age file and
	// the recipients go with the last one.
	ConfigPaths []string
	KeyPath     string
	SecretsDir  string
}

// configPath is the last config file.
func (g *globalFlags) configPath() string { return g.ConfigPaths[len(g.ConfigPaths)-1] }

func NewRootCommand() *cobra.Command {
	flags := &globalFlags{}
	root := &cobra.Command{
		Use:           "princo",
		Short:         "Declarative VPN fleet management",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringArrayVarP(&flags.ConfigPaths, "config", "c", []string{"princo.yaml"}, "Path to princo.yaml; repeat to merge more files over it, later ones winning")
	root.PersistentFlags().StringVarP(&flags.KeyPath, "key", "k", "", "Path to age identity (default ~/.config/princo/key.txt)")

	root.PersistentFlags().StringVar(&flags.SecretsDir, "secrets-dir", "", "Read secrets from files under this directory, one per path (as on a host), instead of where princo.yaml says")

	root.AddCommand(newVersionCommand())
	root.AddCommand(newInitCommand(flags))
	root.AddCommand(newRenderCommand(flags))
	root.AddCommand(newPlanCommand(flags))
	root.AddCommand(newSecretCommand(flags))
	root.AddCommand(newUserCommand(flags))
	root.AddCommand(newDeployCommand(flags))
	root.AddCommand(newStatsCommand(flags))
	root.AddCommand(newRuleSetsCommand(flags))
	root.AddCommand(newHostCommand())
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := cmd.OutOrStdout().Write([]byte("princo " + version.String() + "\n"))
			return err
		},
	}
}

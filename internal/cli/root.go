package cli

import (
	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/version"
)

// Flags shared by every command that loads config + secrets.
type globalFlags struct {
	ConfigPath string
	KeyPath    string
	SecretsDir string
}

func NewRootCommand() *cobra.Command {
	flags := &globalFlags{}
	root := &cobra.Command{
		Use:           "princo",
		Short:         "Declarative VPN fleet management",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&flags.ConfigPath, "config", "c", "princo.yaml", "Path to princo.yaml")
	root.PersistentFlags().StringVarP(&flags.KeyPath, "key", "k", "", "Path to age identity (default ~/.config/princo/key.txt)")

	root.PersistentFlags().StringVar(&flags.SecretsDir, "secrets-dir", "", "Read secrets from files under this directory, one per path (as on a host), instead of where princo.yaml says")

	root.AddCommand(newVersionCommand())
	root.AddCommand(newInitCommand(flags))
	root.AddCommand(newRenderCommand(flags))
	root.AddCommand(newPlanCommand(flags))
	root.AddCommand(newSecretCommand(flags))
	root.AddCommand(newUserCommand(flags))
	root.AddCommand(newDeployCommand(flags))
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

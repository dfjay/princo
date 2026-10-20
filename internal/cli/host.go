package cli

import (
	"encoding/json/v2"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/bundle"
)

func newHostCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Commands princo deploy runs on a node's host",
	}
	cmd.AddCommand(newHostApplyCommand())
	return cmd
}

func newHostApplyCommand() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a bundle read from stdin to this host",
		Long: `Read a bundle that princo deploy built from stdin, write its files,
remove the files the previous bundle had and this one lacks, and restart
the systemd units whose files changed. When a check or a restart fails,
the old files are put back and the units restarted on them. Run it as
root; it prints what it changed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var b bundle.Bundle
			if err := json.UnmarshalRead(cmd.InOrStdin(), &b); err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}
			h, err := bundle.NewHost()
			if err != nil {
				return err
			}
			defer h.Root.Close()
			var changes []bundle.Change
			if check {
				changes, err = h.Diff(&b)
			} else {
				changes, err = h.Apply(cmd.Context(), &b)
			}
			if err != nil {
				return err
			}
			for _, c := range changes {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), c); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Print what would change, and change nothing")
	return cmd
}

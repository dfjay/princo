package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/fleet"
)

func newUserCommand(global *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Add, remove and rotate users",
		Long: `Add, remove and rotate users in princo.yaml along with their UUIDs. A
user's subscription link comes from their UUID; deploy the nodes for a
change to take effect.`,
	}
	cmd.AddCommand(newUserAddCommand(global))
	cmd.AddCommand(newUserRemoveCommand(global))
	cmd.AddCommand(newUserRotateCommand(global))
	return cmd
}

func newUserAddCommand(global *globalFlags) *cobra.Command {
	var nodes []string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a user to princo.yaml and generate their UUID",
		Example: `  princo user add alice             # on all nodes
  princo user add bob --nodes fr,us # on fr and us, in this order`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !fleet.ValidName(name) {
				return fmt.Errorf("user name %q: use lowercase letters, digits, - and _, starting and ending with a letter or digit", name)
			}
			files, err := readConfigFiles(global)
			if err != nil {
				return err
			}
			cfg, err := files.config()
			if err != nil {
				return err
			}
			if _, ok := cfg.Users.Get(name); ok {
				return fmt.Errorf("users.%s already exists", name)
			}
			for _, n := range nodes {
				if _, ok := cfg.Nodes.Get(n); !ok {
					return fmt.Errorf("--nodes: no node named %q", n)
				}
			}
			entry := "{}"
			if len(nodes) > 0 {
				entry = "{ nodes: [" + strings.Join(nodes, ", ") + "] }"
			}
			last := files.last()
			data, err := config.AddEntry(files.data[last], "users", name, entry)
			if err != nil {
				return err
			}
			added := files.with(last, data)
			if _, err := added.config(); err != nil {
				return err
			}
			if err := added.save(files); err != nil {
				return err
			}
			logf(cmd.ErrOrStderr(), "users.%s: added to %s", name, files.name(last))

			err = addUUID(cmd, global, name)
			if err == nil {
				return nil
			}
			if rerr := files.save(added); rerr != nil {
				return fmt.Errorf("%w; removing users.%s from %s also failed: %v", err, name, files.name(last), rerr)
			}
			return fmt.Errorf("%w; users.%s removed from %s again", err, name, files.name(last))
		},
	}
	cmd.Flags().StringSliceVar(&nodes, "nodes", nil, "Nodes the user may use, in the order their app lists them (default all)")
	return cmd
}

// addUUID generates the UUID of a user just added, unless it has one.
func addUUID(cmd *cobra.Command, global *globalFlags, name string) error {
	g, err := newGenerator(cmd, global)
	if err != nil {
		return err
	}
	u, ok := g.userUUID(name)
	if !ok {
		return nil
	}
	if has, err := g.resolver.Has(u.Path); err != nil {
		return err
	} else if has {
		logf(g.log, "%s: kept the value it already has", u.Path)
		return nil
	}
	return g.write(u)
}

func newUserRemoveCommand(global *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a user from princo.yaml and delete their UUID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			g, err := newGenerator(cmd, global)
			if err != nil {
				return err
			}
			files, err := readConfigFiles(global)
			if err != nil {
				return err
			}
			// From every file that has them, or a merge brings them back.
			out, removed := files, false
			for i := range files.paths {
				if c, err := config.Parse(out.data[i]); err != nil {
					return fmt.Errorf("%s: %w", out.paths[i], err)
				} else if _, ok := c.Users.Get(name); !ok {
					continue
				}
				edited, err := config.RemoveEntry(out.data[i], "users", name)
				if err == nil {
					edited, err = config.DropEmpty(edited, "users")
				}
				if err != nil {
					return fmt.Errorf("%s: %w", out.paths[i], err)
				}
				out, removed = out.with(i, edited), true
			}
			if !removed {
				return fmt.Errorf("users.%s doesn't exist", name)
			}
			cfg, err := out.config()
			if err != nil {
				return err
			}
			// The UUID goes first: if that fails, the user is still there to retry.
			restore := func() error { return nil }
			if u, ok := g.userUUID(name); ok {
				if restore, err = g.removeUnused(u, cfg); err != nil {
					return err
				}
			}
			if err := out.save(files); err != nil {
				if rerr := restore(); rerr != nil {
					return fmt.Errorf("%w; restoring the UUID also failed: %v", err, rerr)
				}
				return err
			}
			logf(g.log, "users.%s: removed from princo.yaml", name)
			return nil
		},
	}
}

// removeUnused deletes u's secret unless cfg still reads it, returning
// how to put it back.
func (g *generator) removeUnused(u fleet.SecretUse, cfg *config.Config) (restore func() error, err error) {
	restore = func() error { return nil }
	if slices.ContainsFunc(fleet.Secrets(cfg), func(v fleet.SecretUse) bool { return g.sameSecret(v.Path, u.Path) }) {
		logf(g.log, "%s: kept, princo.yaml still uses it", u.Path)
		return restore, nil
	}
	prev, ok, err := g.value(u.Path)
	if err != nil || !ok {
		return restore, err
	}
	if err := g.resolver.Delete(u.Path); err != nil {
		return nil, err
	}
	logf(g.log, "%s: deleted from %s", u.Path, g.resolver.Locate(u.Path))
	return func() error { return g.resolver.Set(u.Path, prev) }, nil
}

func newUserRotateCommand(global *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <name>",
		Short: "Replace a user's UUID, and with it their subscription link",
		Long: `Replace a user's UUID. Their subscription link changes with it: once the
nodes are deployed, the old link and profiles stop working. Print the new
links with princo render --user <name> --links.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			g, err := newGenerator(cmd, global)
			if err != nil {
				return err
			}
			if _, exists := g.cfg.Users.Get(name); !exists {
				return fmt.Errorf("no user named %q", name)
			}
			u, ok := g.userUUID(name)
			if !ok {
				return fmt.Errorf("users.%s.uuid is written in princo.yaml; change it there", name)
			}
			for _, v := range g.uses {
				if v.Field != u.Field && g.sameSecret(v.Path, u.Path) {
					return fmt.Errorf("%s: %s reads the same UUID; give each its own before rotating", u.Path, v.Field)
				}
			}
			if err := g.write(u); err != nil {
				return err
			}
			logf(g.log, "deploy the nodes, then send %s the new links: princo render --user %s --links", name, name)
			return nil
		},
	}
}

package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/secrets"
)

func newSecretGenCommand(global *globalFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "gen [path...]",
		Short: "Generate the secrets princo.yaml uses",
		Long: `Generate secrets princo.yaml uses and store them where its secrets: block
maps them: user and chain UUIDs, Reality key pairs and the Hysteria2
obfuscation password. A Reality key's public half goes into the node's
reality.public_key in princo.yaml.

Without paths, generates every one that is missing. WARP credentials come
from a WARP account; store them with princo secret set.`,
		Example: `  princo secret gen                     # every missing secret
  princo secret gen nodes/fr/reality    # one that is missing
  princo secret gen --force users/alice # replace alice's UUID`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if force && len(args) == 0 {
				return fmt.Errorf("--force needs the paths to replace")
			}
			g, err := newGenerator(cmd, global)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return g.missing()
			}
			for _, path := range args {
				if err := g.gen(path, force); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Replace secrets that already have a value")
	return cmd
}

type generator struct {
	global   *globalFlags
	cfg      *config.Config
	resolver *secrets.Resolver
	uses     []fleet.SecretUse
	log      io.Writer
}

func newGenerator(cmd *cobra.Command, global *globalFlags) (*generator, error) {
	cfg, err := loadConfig(global)
	if err != nil {
		return nil, err
	}
	resolver, err := newResolver(global, cfg)
	if err != nil {
		return nil, err
	}
	return &generator{global: global, cfg: cfg, resolver: resolver, uses: fleet.Secrets(cfg), log: cmd.ErrOrStderr()}, nil
}

// missing generates every secret without a value that princo can make.
func (g *generator) missing() error {
	made := 0
	for _, u := range g.distinct() {
		has, err := g.resolver.Has(u.Path)
		if err != nil {
			return err
		}
		switch {
		case has:
		case u.Kind == fleet.SecretExternal:
			logf(g.log, "%s: missing; it comes from outside princo, store it with princo secret set", u.Path)
		default:
			if err := g.write(u); err != nil {
				return err
			}
			made++
		}
	}
	if made == 0 {
		logf(g.log, "no secrets to generate")
	}
	return nil
}

// gen generates the secret at path, replacing its value only with force.
func (g *generator) gen(path string, force bool) error {
	u, ok := g.use(func(u fleet.SecretUse) bool { return u.Path == path })
	if !ok {
		return fmt.Errorf("%s: princo.yaml doesn't use this secret", path)
	}
	if u.Kind == fleet.SecretExternal {
		return fmt.Errorf("%s: comes from outside princo; store it with princo secret set", path)
	}
	if !force {
		has, err := g.resolver.Has(path)
		if err != nil {
			return err
		}
		if has {
			return fmt.Errorf("%s: already has a value; pass --force to replace it", path)
		}
	}
	return g.write(u)
}

// distinct lists each secret once, by its first use.
func (g *generator) distinct() []fleet.SecretUse {
	seen := map[string]bool{}
	return slices.DeleteFunc(slices.Clone(g.uses), func(u fleet.SecretUse) bool {
		dup := seen[u.Path]
		seen[u.Path] = true
		return dup
	})
}

// value returns the secret at path, if it has one.
func (g *generator) value(path string) (string, bool, error) {
	has, err := g.resolver.Has(path)
	if err != nil || !has {
		return "", false, err
	}
	v, err := g.resolver.Get(path)
	return v, err == nil, err
}

// sameSecret reports whether paths a and b are stored in the same place.
func (g *generator) sameSecret(a, b string) bool {
	return g.resolver.Identity(a) == g.resolver.Identity(b)
}

func (g *generator) use(match func(fleet.SecretUse) bool) (fleet.SecretUse, bool) {
	i := slices.IndexFunc(g.uses, match)
	if i < 0 {
		return fleet.SecretUse{}, false
	}
	return g.uses[i], true
}

// userUUID finds where user's UUID is stored; none for a literal uuid.
func (g *generator) userUUID(user string) (fleet.SecretUse, bool) {
	return g.use(func(u fleet.SecretUse) bool { return u.Field == "users."+user+".uuid" })
}

func (g *generator) write(u fleet.SecretUse) error {
	var value, public string
	switch u.Kind {
	case fleet.SecretUUID:
		value = secrets.NewUUID()
	case fleet.SecretPassword:
		value = secrets.NewHex(16)
	case fleet.SecretRealityKey:
		var err error
		if value, public, err = secrets.NewRealityKeyPair(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: princo can't generate it", u.Path)
	}
	if public == "" {
		return g.set(u.Path, value)
	}

	commit, err := g.publicKeyEdit(u.Path, public)
	if err != nil {
		return err
	}
	prev, had, err := g.value(u.Path)
	if err != nil {
		return err
	}
	if err := g.set(u.Path, value); err != nil {
		return err
	}
	if err := commit(); err != nil {
		var uerr error
		if had {
			uerr = g.resolver.Set(u.Path, prev)
		} else {
			uerr = g.resolver.Delete(u.Path)
		}
		if uerr != nil {
			return fmt.Errorf("%w; restoring %s also failed: %v", err, u.Path, uerr)
		}
		return fmt.Errorf("%w; %s left as it was", err, u.Path)
	}
	return nil
}

func (g *generator) set(path, value string) error {
	if err := g.resolver.Set(path, value); err != nil {
		return err
	}
	logf(g.log, "%s: generated in %s", path, g.resolver.Locate(path))
	return nil
}

// publicKeyEdit prepares writing public next to every field that reads the
// private key at path, failing before the key changes; commit saves it.
// The key goes to the last config file that has the field.
func (g *generator) publicKeyEdit(path, public string) (commit func() error, err error) {
	files, err := readConfigFiles(g.global)
	if err != nil {
		return nil, err
	}
	var set, absent []string
	wrote := map[string]bool{}
	var fields []string
	out := files
	for _, u := range g.uses {
		if u.Path != path {
			continue
		}
		keys := strings.Split(u.Field, ".")
		keys[len(keys)-1] = "public_key"
		field := strings.Join(keys, ".")
		fields = append(fields, field)
		for i := out.last(); i >= 0 && !wrote[field]; i-- {
			edited, ok, err := config.SetValue(out.data[i], keys, public)
			if err != nil {
				return nil, fmt.Errorf("%s: %w; its public key is %s", out.paths[i], err, public)
			}
			if ok {
				out = out.with(i, edited)
				set = append(set, field+": updated in "+out.name(i))
				wrote[field] = true
			}
		}
		if !wrote[field] {
			absent = append(absent, field)
		}
	}
	// A YAML merge key can supply the field where princo can't edit it.
	cfg, err := out.config()
	if err != nil {
		return nil, fmt.Errorf("%w; its public key is %s", err, public)
	}
	for _, field := range fields {
		var v string // fields are nodes.<name>.reality.public_key
		if n, ok := cfg.Nodes.Get(strings.Split(field, ".")[1]); ok && n.Reality != nil {
			v = n.Reality.PublicKey
		}
		want := ""
		if wrote[field] {
			want = public
		}
		if v != want {
			return nil, fmt.Errorf("%s: can't set it where its value comes from, such as a YAML merge key; write it out in the config's last file that sets it, then generate %s again", field, path)
		}
	}
	return func() error {
		if err := out.save(files); err != nil {
			return err
		}
		for _, s := range set {
			logf(g.log, "%s", s)
		}
		for _, f := range absent {
			logf(g.log, "%s: add it to %s: %s", f, files.name(files.last()), public)
		}
		return nil
	}, nil
}

func logf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

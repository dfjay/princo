package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/secrets"
)

// initConfig is the fleet princo init starts from; %s is the short ID.
const initConfig = `# One node, two users. Their apps connect over VLESS-Reality or
# Hysteria2 and pick up both from the subscription site.
princo: v1

defaults:
  acme_email: you@example.com

nodes:
  nl:
    address: nl.example.com
    reality:
      server_name: www.microsoft.com # a real HTTPS site the node imitates
      short_id: %s
      public_key: <public key> # set by princo secret gen nodes/nl/reality
    hysteria2: {}

users:
  alice: {}
  bob: {}

client:
  groups:
    proxy: { nodes: all }
  rules:
    - { match: [ip:private], action: direct }
  final: proxy

subscription:
  node: nl
  domain: subs.example.com
`

func newInitCommand(global *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Start a fleet: princo.yaml, an age key and the secrets it needs",
		Long: `Start a fleet in the directory of --config: write a princo.yaml with one
node and two users and generate its secrets into secrets.age. Without a
recipients file there, princo init writes one for the age identity at
--key, creating the identity unless it exists.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := global.ConfigPath
			if fileExists(path) {
				return fmt.Errorf("%s already exists", path)
			}
			log := cmd.ErrOrStderr()
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if p := recipientsPath(global); fileExists(p) {
				if err := checkRecipients(global, p); err != nil {
					return err
				}
			} else {
				recipient, err := ensureIdentity(global, log)
				if err != nil {
					return err
				}
				if err := os.WriteFile(p, []byte(recipient+"\n"), 0o644); err != nil {
					return err
				}
				logf(log, "%s: written", p)
			}
			if err := os.WriteFile(path, fmt.Appendf(nil, initConfig, secrets.NewHex(4)), 0o644); err != nil {
				return err
			}
			logf(log, "%s: written", path)

			g, err := newGenerator(cmd, global)
			if err != nil {
				return err
			}
			if err := g.existingRealityKeys(); err != nil {
				return err
			}
			if err := g.missing(); err != nil {
				return err
			}
			logf(log, "\nNext, set your domains and ACME email in %s, then deploy.", path)
			return nil
		},
	}
}

// ensureIdentity creates the age identity unless it exists, and returns
// its recipient.
func ensureIdentity(global *globalFlags, log io.Writer) (string, error) {
	path := identityPath(global)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		id, err := age.GenerateX25519Identity()
		if err == nil {
			_, err = f.WriteString(id.String() + "\n")
		}
		if err = errors.Join(err, f.Close()); err != nil {
			_ = os.Remove(path)
			return "", err
		}
		logf(log, "%s: created; keep this key private and backed up", path)
		return id.Recipient().String(), nil
	} else if !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	recipients, err := secrets.IdentityRecipients(path)
	if err != nil {
		return "", err
	}
	if len(recipients) == 0 {
		return "", fmt.Errorf("%s has only plugin identities; write the recipients file by hand", path)
	}
	return recipients[0], nil
}

// checkRecipients makes sure the identity at --key can read secrets
// encrypted to the recipients file p.
func checkRecipients(global *globalFlags, p string) error {
	path := identityPath(global)
	if !fileExists(path) {
		return fmt.Errorf("%s: no age identity to read secrets encrypted to %s; pass --key", path, p)
	}
	return secrets.CheckRecipients(path, p)
}

// existingRealityKeys fills in the public keys of Reality private keys the
// secrets already hold.
func (g *generator) existingRealityKeys() error {
	for _, u := range g.distinct() {
		if u.Kind != fleet.SecretRealityKey {
			continue
		}
		private, ok, err := g.value(u.Path)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		public, err := secrets.RealityPublicKey(private)
		if err != nil {
			return fmt.Errorf("%s: %w", u.Path, err)
		}
		commit, err := g.publicKeyEdit(u.Path, public)
		if err != nil {
			return err
		}
		if err := commit(); err != nil {
			return err
		}
	}
	return nil
}

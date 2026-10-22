package secrets

import (
	"fmt"
	"os"
	"slices"

	"filippo.io/age"
)

// IdentityRecipients returns the recipients of the X25519 and hybrid
// identities at path; plugin identities aren't listed.
func IdentityRecipients(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read identity %s: %w", path, err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity %s: %w", path, err)
	}
	var out []string
	for _, id := range ids {
		switch id := id.(type) {
		case *age.X25519Identity:
			out = append(out, id.Recipient().String())
		case *age.HybridIdentity:
			out = append(out, id.Recipient().String())
		}
	}
	return out, nil
}

// CheckRecipients makes sure the identity at identityPath can read files
// encrypted to the recipients file at recipientsPath. An identity of plugin
// keys only can't be checked and passes.
func CheckRecipients(identityPath, recipientsPath string) error {
	own, err := IdentityRecipients(identityPath)
	if err != nil || len(own) == 0 {
		return err
	}
	listed, err := LoadRecipients(recipientsPath)
	if err != nil {
		return err
	}
	for _, r := range listed {
		if s, ok := r.(fmt.Stringer); ok && slices.Contains(own, s.String()) {
			return nil
		}
	}
	return fmt.Errorf("%s doesn't list the identity at %s; add %s to it", recipientsPath, identityPath, own[0])
}

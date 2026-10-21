package fleet

import (
	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/secrets"
)

// SecretKind is what a secret holds, and so how princo can make one.
type SecretKind int

const (
	// SecretExternal comes from elsewhere, such as a WARP account.
	SecretExternal SecretKind = iota
	SecretUUID
	// SecretRealityKey is a Reality private key; its public half goes
	// next to it in princo.yaml, at public_key.
	SecretRealityKey
	SecretPassword
)

// SecretUse is a secret princo.yaml reads.
type SecretUse struct {
	Path string
	// Field is where in princo.yaml it is used, e.g. users.alice.uuid.
	Field string
	Kind  SecretKind
}

// Secrets lists the fields of cfg that read secrets, in the order Build
// resolves them; fields sharing a secret each appear. It works on a config
// that doesn't validate yet, so secrets can be made before the rest of it
// is filled in.
func Secrets(cfg *config.Config) []SecretUse {
	b := newBuilder(cfg, secrets.AllPlaceholders{})
	b.nodes()
	b.egress()
	b.users()
	return b.uses
}

// ValidName reports whether name may name a node, user or client group.
func ValidName(name string) bool { return nameRe.MatchString(name) }

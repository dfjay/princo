package secrets

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// SecretOrPlain holds either a literal value or a reference to a path in a
// secret store. Exactly one of Plain / SecretPath is set after unmarshalling.
type SecretOrPlain struct {
	Plain      string
	SecretPath string
}

// IsPlain reports whether this is a literal (non-secret) value.
func (s SecretOrPlain) IsPlain() bool { return s.SecretPath == "" }

// UnmarshalYAML accepts either a plain string or a `!secret <path>` scalar.
func (s *SecretOrPlain) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected scalar, got %v", value.Line, value.Kind)
	}
	switch value.Tag {
	case "!secret":
		s.SecretPath = value.Value
		return nil
	case "!!str", "", "!!null":
		s.Plain = value.Value
		return nil
	default:
		return fmt.Errorf("line %d: unsupported tag %q for secret-or-plain field", value.Line, value.Tag)
	}
}

// Getter looks secrets up by path; *Store implements it.
type Getter interface {
	Get(path string) (string, error)
}

// Resolve returns the literal value, or looks up the reference in the store.
func (s SecretOrPlain) Resolve(store Getter) (string, error) {
	if s.IsPlain() {
		return s.Plain, nil
	}
	v, err := store.Get(s.SecretPath)
	if err != nil {
		return "", fmt.Errorf("resolve !secret %s: %w", s.SecretPath, err)
	}
	return v, nil
}

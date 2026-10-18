package secrets

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// Store is an in-memory view of the decrypted secrets file.
// It is loaded once via Open and queried via Get/Set/List.
type Store struct {
	values map[string]any
}

// Open reads an armored age-encrypted YAML file and decrypts it with the
// identity at identityPath. The decrypted content must be a YAML mapping.
func Open(path, identityPath string) (*Store, error) {
	idFile, err := os.Open(identityPath)
	if err != nil {
		return nil, fmt.Errorf("read identity %s: %w", identityPath, err)
	}
	defer idFile.Close()
	identities, err := age.ParseIdentities(idFile)
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}

	enc, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer enc.Close()

	armored := armor.NewReader(enc)
	plain, err := age.Decrypt(armored, identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}
	body, err := io.ReadAll(plain)
	if err != nil {
		return nil, fmt.Errorf("read decrypted: %w", err)
	}

	var values map[string]any
	if err := yaml.Unmarshal(body, &values); err != nil {
		return nil, fmt.Errorf("parse decrypted yaml: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	return &Store{values: values}, nil
}

// NewStore wraps already-decrypted values, e.g. test fixtures.
func NewStore(values map[string]any) *Store { return &Store{values: values} }

// Save encrypts the given map as armored age and atomically writes it to path.
// recipientsPath is a text file with one age public key per line.
func Save(path, recipientsPath string, values map[string]any) error {
	recipients, err := loadRecipients(recipientsPath)
	if err != nil {
		return err
	}
	body, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	var encrypted bytes.Buffer
	armored := armor.NewWriter(&encrypted)
	w, err := age.Encrypt(armored, recipients...)
	if err != nil {
		return fmt.Errorf("init encryption: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("encrypt body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close encryptor: %w", err)
	}
	if err := armored.Close(); err != nil {
		return fmt.Errorf("close armor: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encrypted.Bytes(), 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

func loadRecipients(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recipients %s: %w", path, err)
	}
	defer f.Close()
	recipients, err := age.ParseRecipients(f)
	if err != nil {
		return nil, fmt.Errorf("parse recipients: %w", err)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients in %s", path)
	}
	return recipients, nil
}

// splitPath splits "a/b.c" → ["a", "b", "c"]. Both / and . work, in any mix.
func splitPath(p string) []string {
	out := []string{}
	for _, part := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '.'
	}) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Get returns the string value at the given dot/slash-separated path.
func (s *Store) Get(path string) (string, error) {
	parts := splitPath(path)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty secret path")
	}
	cur := any(s.values)
	for i, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("secret not found: %s (parent at %q is not a map)", path, strings.Join(parts[:i], "/"))
		}
		next, ok := m[part]
		if !ok {
			return "", fmt.Errorf("secret not found: %s", path)
		}
		cur = next
	}
	str, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("secret %s is not a string (got %T)", path, cur)
	}
	return str, nil
}

// Set writes a string value at the path, creating intermediate maps.
func (s *Store) Set(path, value string) error {
	parts := splitPath(path)
	if len(parts) == 0 {
		return fmt.Errorf("empty secret path")
	}
	if s.values == nil {
		s.values = map[string]any{}
	}
	m := s.values
	for _, part := range parts[:len(parts)-1] {
		next, ok := m[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[part] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = value
	return nil
}

// Delete removes the value at the path. No-op if missing.
func (s *Store) Delete(path string) error {
	parts := splitPath(path)
	if len(parts) == 0 {
		return fmt.Errorf("empty secret path")
	}
	m := s.values
	for _, part := range parts[:len(parts)-1] {
		next, ok := m[part].(map[string]any)
		if !ok {
			return nil
		}
		m = next
	}
	delete(m, parts[len(parts)-1])
	return nil
}

// List returns all leaf paths, flattened with "/" separators.
func (s *Store) List() []string {
	var out []string
	walkLeaves(s.values, "", &out)
	return out
}

func walkLeaves(node any, prefix string, out *[]string) {
	m, ok := node.(map[string]any)
	if !ok {
		*out = append(*out, prefix)
		return
	}
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "/" + k
		}
		walkLeaves(v, key, out)
	}
}

// Values returns the underlying map (for Save).
func (s *Store) Values() map[string]any { return s.values }

package secrets

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"regexp"
	"slices"
)

// Placeholder stands in for the secret at path when its value isn't known.
// It is unique per path and made of characters no JSON or URL escaping
// touches, so the paths a rendered file used can be read back from it.
func Placeholder(path string) string {
	return "princosecret_" + hex.EncodeToString([]byte(path)) + "_"
}

var placeholderRe = regexp.MustCompile(`princosecret_([0-9a-f]+)_`)

// Placeholders returns the secret paths whose placeholders occur in data,
// sorted and without duplicates.
func Placeholders(data []byte) []string {
	var out []string
	for _, m := range placeholderRe.FindAllSubmatch(data, -1) {
		path, err := hex.DecodeString(string(m[1]))
		if err == nil {
			out = append(out, string(path))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// AllPlaceholders answers every path with its placeholder: rendering with
// it shows which secrets the output needs without knowing any of them.
type AllPlaceholders struct{}

func (AllPlaceholders) Get(path string) (string, error) { return Placeholder(path), nil }

// OrPlaceholder answers from g, or with a placeholder for secrets g doesn't
// have. A host holds only its own node's secrets, while the fleet names all
// of them; the caller checks the output for placeholders that are left.
type OrPlaceholder struct{ Getter }

func (o OrPlaceholder) Get(path string) (string, error) {
	v, err := o.Getter.Get(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Placeholder(path), nil
	}
	return v, err
}

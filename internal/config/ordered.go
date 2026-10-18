package config

import (
	"bytes"
	"fmt"
	"iter"

	"gopkg.in/yaml.v3"
)

// Ordered is a YAML mapping that remembers the order its keys were written
// in, for places where that order is user-visible (selectors in a client
// app, DNS servers). Values are decoded strictly: unknown fields are errors.
type Ordered[V any] struct {
	keys   []string
	values map[string]V
}

// Len reports the number of entries.
func (o Ordered[V]) Len() int { return len(o.keys) }

// Get returns the value for key and whether it is present.
func (o Ordered[V]) Get(key string) (V, bool) {
	v, ok := o.values[key]
	return v, ok
}

// Keys returns the keys in document order.
func (o Ordered[V]) Keys() []string { return o.keys }

// All iterates over entries in document order.
func (o Ordered[V]) All() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		for _, k := range o.keys {
			if !yield(k, o.values[k]) {
				return
			}
		}
	}
}

// OrderedOf builds an Ordered from key/value pairs; for tests and defaults.
func OrderedOf[V any](pairs ...any) Ordered[V] {
	o := Ordered[V]{values: map[string]V{}}
	for i := 0; i+1 < len(pairs); i += 2 {
		k := pairs[i].(string)
		o.keys = append(o.keys, k)
		o.values[k] = pairs[i+1].(V)
	}
	return o
}

func (o *Ordered[V]) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping", node.Line)
	}
	o.keys = nil
	o.values = make(map[string]V, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode, valueNode := node.Content[i], node.Content[i+1]
		key := keyNode.Value
		if _, dup := o.values[key]; dup {
			return fmt.Errorf("line %d: duplicate key %q", keyNode.Line, key)
		}
		var v V
		if err := decodeStrict(valueNode, &v); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		o.keys = append(o.keys, key)
		o.values[key] = v
	}
	return nil
}

// decodeStrict decodes a node rejecting unknown fields. yaml.Node.Decode
// ignores the decoder's KnownFields setting, so round-trip through bytes.
func decodeStrict(node *yaml.Node, out any) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

package config

import (
	"errors"
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
)

// File is one file of a config, as read from Path.
type File struct {
	Path string
	Data []byte
}

// Merge parses files and merges each over the ones before it. Mappings
// merge key by key; any other value, a list included, replaces the earlier
// one, except a null, which leaves it as it is. A key keeps the place where
// it was first written. Each file must parse on its own, and the paths in
// its secrets: block are relative to its directory.
func Merge(files []File) (*Config, error) {
	if len(files) == 0 {
		return nil, errors.New("no config files")
	}
	if len(files) == 1 {
		return Parse(files[0].Data)
	}
	var merged *yaml.Node
	secretFiles := map[string]int{}
	for i, f := range files {
		// Merged with aliases resolved, as merging can replace an anchor.
		_, root, err := parse(f.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		if _, v := lookupKey(root, "secrets"); v != nil && v.Kind == yaml.MappingNode {
			kept := v.Content[:0]
			for j := 0; j+1 < len(v.Content); j += 2 {
				if !isNull(v.Content[j+1]) {
					secretFiles[v.Content[j].Value] = i
					kept = append(kept, v.Content[j], v.Content[j+1])
				}
			}
			v.Content = kept
		}
		if merged == nil {
			merged = root
		} else {
			merged = mergeNode(merged, root)
		}
	}
	data, err := yaml.Marshal(merged)
	if err != nil {
		return nil, err
	}
	cfg, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("merged config: %w", err)
	}
	cfg.secretFiles = secretFiles
	return cfg, nil
}

// mergeNode returns over merged onto base, leaving both as they are.
func mergeNode(base, over *yaml.Node) *yaml.Node {
	if isNull(over) {
		return base
	}
	if base.Kind != yaml.MappingNode || over.Kind != yaml.MappingNode {
		return over
	}
	out := *base
	out.Content = slices.Clone(base.Content)
	at := make(map[string]int, len(out.Content)/2) // key → index of its value
	for i := 0; i+1 < len(out.Content); i += 2 {
		at[out.Content[i].Value] = i + 1
	}
	for i := 0; i+1 < len(over.Content); i += 2 {
		k, v := over.Content[i], over.Content[i+1]
		if j, ok := at[k.Value]; ok {
			out.Content[j] = mergeNode(out.Content[j], v)
			continue
		}
		out.Content = append(out.Content, k, v)
		at[k.Value] = len(out.Content) - 1
	}
	return &out
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// maxNodes bounds a document with its aliases resolved, which aliases of
// aliases grow exponentially.
const maxNodes = 100_000

// normalize parses the first document in data and resolves its aliases
// and merge keys, reporting whether it had any; an empty one yields nil.
func normalize(data []byte) (root *yaml.Node, resolved bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, err
	}
	if len(doc.Content) == 0 {
		return nil, false, nil
	}
	e := expander{visiting: map[*yaml.Node]bool{}}
	root, err = e.expand(doc.Content[0])
	return root, e.resolved, err
}

type expander struct {
	visiting map[*yaml.Node]bool
	nodes    int
	resolved bool
}

// expand copies n with aliases replaced by what they refer to, merge keys
// flattened and anchors dropped.
func (e *expander) expand(n *yaml.Node) (*yaml.Node, error) {
	if e.nodes++; e.nodes > maxNodes {
		return nil, fmt.Errorf("more than %d nodes with its aliases resolved", maxNodes)
	}
	if n.Kind == yaml.AliasNode {
		if e.visiting[n.Alias] {
			return nil, fmt.Errorf("line %d: alias *%s refers to itself", n.Line, n.Value)
		}
		e.resolved = true
		return e.expand(n.Alias)
	}
	e.visiting[n] = true
	defer delete(e.visiting, n)
	out := *n
	if out.Anchor != "" {
		out.Anchor, e.resolved = "", true
	}
	out.Content = make([]*yaml.Node, len(n.Content))
	for i, c := range n.Content {
		x, err := e.expand(c)
		if err != nil {
			return nil, err
		}
		out.Content[i] = x
	}
	if out.Kind != yaml.MappingNode {
		return &out, nil
	}
	flat, err := flattenMerges(&out)
	if flat != &out {
		e.resolved = true
	}
	return flat, err
}

// flattenMerges replaces a mapping's `<<` keys with the entries they bring
// in, in their place. As in YAML, the mapping's own keys win, then earlier
// merged mappings over later ones.
func flattenMerges(m *yaml.Node) (*yaml.Node, error) {
	own := map[string]bool{}
	merges := false
	for i := 0; i+1 < len(m.Content); i += 2 {
		if isMergeKey(m.Content[i]) {
			merges = true
		} else {
			own[m.Content[i].Value] = true
		}
	}
	if !merges {
		return m, nil
	}
	out := *m
	out.Content = nil
	added := map[string]bool{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if !isMergeKey(k) {
			out.Content = append(out.Content, k, v)
			continue
		}
		sources := []*yaml.Node{v}
		if v.Kind == yaml.SequenceNode {
			sources = v.Content
		}
		for _, src := range sources {
			if src.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("line %d: << merges mappings only", k.Line)
			}
			for j := 0; j+1 < len(src.Content); j += 2 {
				key := src.Content[j].Value
				if own[key] || added[key] {
					continue
				}
				added[key] = true
				out.Content = append(out.Content, src.Content[j], src.Content[j+1])
			}
		}
	}
	return &out, nil
}

func isMergeKey(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!merge"
}

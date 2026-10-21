package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// The edits below change princo.yaml as text, so comments, blank lines and
// flow style stay as the user wrote them. Each one checks that the result
// parses to the old document with just the intended change.

// SetValue replaces the scalar at keys, e.g. nodes, fr, reality,
// public_key. It reports false, changing nothing, when the key is absent.
func SetValue(data []byte, keys []string, value string) ([]byte, bool, error) {
	root, err := parseRoot(data)
	if err != nil {
		return nil, false, err
	}
	node := root
	for _, k := range keys {
		_, v := lookupKey(node, k)
		if v == nil {
			return data, false, nil
		}
		node = v
	}
	where := strings.Join(keys, ".")
	if node.Kind != yaml.ScalarNode {
		return nil, false, fmt.Errorf("%s: not a single value", where)
	}
	lines := splitLines(data)
	line := []rune(lines[node.Line-1])
	start := node.Column - 1
	end := scalarEnd(line, start, node)
	if end < 0 {
		return nil, false, fmt.Errorf("%s: can't edit this value in place; set it to %s by hand", where, value)
	}
	text := scalarText(value)
	if node.Tag == "!!null" && node.Value == "" {
		text = " " + text
	}
	lines[node.Line-1] = string(line[:start]) + text + string(line[end:])
	out := []byte(strings.Join(lines, ""))
	if err := checkEdit(data, out, func(doc map[string]any) {
		m := doc
		for _, k := range keys[:len(keys)-1] {
			m, _ = m[k].(map[string]any)
		}
		m[keys[len(keys)-1]] = value
	}); err != nil {
		return nil, false, fmt.Errorf("%s: %w", where, err)
	}
	return out, true, nil
}

// AddEntry adds `name: value` to the top-level mapping section, after its
// last entry; value is YAML text such as `{}`.
func AddEntry(data []byte, section, name, value string) ([]byte, error) {
	root, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := yaml.Unmarshal([]byte(value), &decoded); err != nil {
		return nil, fmt.Errorf("%s.%s: %w", section, name, err)
	}
	lines := splitLines(data)
	if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
		lines[len(lines)-1] += "\n"
	}
	entry := func(indent int) string { return strings.Repeat(" ", indent) + scalarText(name) + ": " + value + "\n" }

	k, v := lookupKey(root, section)
	switch {
	case k == nil:
		lines = append(lines, "\n", section+":\n", entry(2))
	case v.Kind == yaml.ScalarNode && v.Tag == "!!null" && v.Line == k.Line && v.Value == "":
		lines = insert(lines, k.Line, entry(2))
	case v.Kind == yaml.MappingNode && v.Style&yaml.FlowStyle == 0:
		if e, _ := lookupKey(v, name); e != nil {
			return nil, fmt.Errorf("%s.%s already exists", section, name)
		}
		indent := v.Content[0].Column - 1
		lines = insert(lines, sectionEnd(lines, root, k, indent), entry(indent))
	default:
		return nil, fmt.Errorf("%s: not written as an indented block; add %s by hand", section, name)
	}
	out := []byte(strings.Join(lines, ""))
	if err := checkEdit(data, out, func(doc map[string]any) {
		m, _ := doc[section].(map[string]any)
		if m == nil {
			m = map[string]any{}
			doc[section] = m
		}
		m[name] = decoded
	}); err != nil {
		return nil, fmt.Errorf("%s.%s: %w", section, name, err)
	}
	return out, nil
}

// RemoveEntry deletes name and its value from the top-level mapping section.
func RemoveEntry(data []byte, section, name string) ([]byte, error) {
	root, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	k, v := lookupKey(root, section)
	if v == nil || v.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s.%s doesn't exist", section, name)
	}
	if v.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("%s: not written as an indented block; remove %s by hand", section, name)
	}
	lines := splitLines(data)
	indent := v.Content[0].Column - 1
	for i := 0; i+1 < len(v.Content); i += 2 {
		if v.Content[i].Value != name {
			continue
		}
		start := v.Content[i].Line - 1
		end := sectionEnd(lines, root, k, indent)
		if i+2 < len(v.Content) {
			end = contentEnd(lines, v.Content[i+2].Line-1, indent+1)
		}
		out := []byte(strings.Join(append(lines[:start:start], lines[end:]...), ""))
		if err := checkEdit(data, out, func(doc map[string]any) {
			m := doc[section].(map[string]any)
			if delete(m, name); len(m) == 0 {
				doc[section] = nil
			}
		}); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", section, name, err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s.%s doesn't exist", section, name)
}

func parseRoot(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse princo.yaml: %w", err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("princo.yaml holds more than one YAML document; edit it by hand")
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse princo.yaml: not a mapping")
	}
	return doc.Content[0], nil
}

func lookupKey(m *yaml.Node, key string) (k, v *yaml.Node) {
	if m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// splitLines splits data into lines that keep their newlines.
func splitLines(data []byte) []string {
	var out []string
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n') + 1
		if i == 0 {
			i = len(data)
		}
		out = append(out, string(data[:i]))
		data = data[i:]
	}
	return out
}

func insert(lines []string, at int, line string) []string {
	return append(lines[:at:at], append([]string{line}, lines[at:]...)...)
}

// sectionEnd is the index of the line after the top-level section whose
// key is k and whose entries are indented by indent.
func sectionEnd(lines []string, root, k *yaml.Node, indent int) int {
	next := len(lines)
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i] == k && i+2 < len(root.Content) {
			next = root.Content[i+2].Line - 1
		}
	}
	return contentEnd(lines, next, indent)
}

// contentEnd moves back from line index next over blank lines and comments
// indented less than indent, which belong to what follows.
func contentEnd(lines []string, next, indent int) int {
	for next > 0 {
		l := lines[next-1]
		trimmed := strings.TrimLeft(l, " ")
		if strings.TrimSpace(l) != "" && (!strings.HasPrefix(trimmed, "#") || len(l)-len(trimmed) >= indent) {
			break
		}
		next--
	}
	return next
}

// scalarEnd finds where the scalar node starting at line[start] ends, or
// -1 when it isn't on this line alone.
func scalarEnd(line []rune, start int, node *yaml.Node) int {
	switch {
	case node.Style&yaml.DoubleQuotedStyle != 0:
		for i := start + 1; i < len(line); i++ {
			switch line[i] {
			case '\\':
				i++
			case '"':
				return i + 1
			}
		}
	case node.Style&yaml.SingleQuotedStyle != 0:
		for i := start + 1; i < len(line); i++ {
			if line[i] == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				return i + 1
			}
		}
	case node.Style == 0:
		v := []rune(node.Value)
		if start+len(v) <= len(line) && string(line[start:start+len(v)]) == node.Value {
			return start + len(v)
		}
	}
	return -1
}

var plainRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// scalarText writes value plain when that reads back as the same string,
// else double-quoted.
func scalarText(value string) string {
	var back any
	if plainRe.MatchString(value) && yaml.Unmarshal([]byte(value), &back) == nil && back == value {
		return value
	}
	q, _ := json.Marshal(value)
	return string(q)
}

// checkEdit makes sure edited parses to old with change applied.
func checkEdit(old, edited []byte, change func(doc map[string]any)) error {
	var want, got any
	if err := yaml.Unmarshal(old, &want); err != nil {
		return err
	}
	if err := yaml.Unmarshal(edited, &got); err != nil {
		return fmt.Errorf("edit broke princo.yaml: %w", err)
	}
	doc, _ := stringKeys(want).(map[string]any)
	if doc == nil {
		doc = map[string]any{}
	}
	change(doc)
	want, got = doc, stringKeys(got)
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("edit changed more than intended; princo.yaml left as it was")
	}
	return nil
}

// stringKeys turns the map[any]any YAML gives a mapping with keys such as
// 123 into the map[string]any princo reads it as.
func stringKeys(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = stringKeys(e)
		}
	case map[any]any:
		m := make(map[string]any, len(v))
		for k, e := range v {
			m[fmt.Sprint(k)] = stringKeys(e)
		}
		return m
	case []any:
		for i, e := range v {
			v[i] = stringKeys(e)
		}
	}
	return v
}

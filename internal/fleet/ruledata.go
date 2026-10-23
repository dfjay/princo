package fleet

import (
	"cmp"
	_ "embed"
	"encoding/json/v2"
	"maps"
	"net/url"
	"slices"
	"strings"
)

// RuleData is where the fleet's geoip and geosite data comes from. Every
// node and client profile is built from the same, so a client sends
// traffic where the node agrees with it.
type RuleData struct {
	GeoIP   RuleSource `json:"geoip"`
	Geosite RuleSource `json:"geosite"`
}

// RuleSource is one kind of rule data: a preset's or a URL's.
type RuleSource struct {
	// Preset names it, or is empty for a URL of the user's.
	Preset string `json:"preset,omitempty"`
	// URL is a geoip.dat or geosite.dat, or for geoip a MaxMind-format
	// .mmdb, optionally gzipped. {month} stands for the current one, as
	// 2026-10.
	URL string `json:"url"`
	// Nix is where the NixOS module takes a preset's data from.
	Nix *NixSource `json:"nix,omitempty"`
}

// NixSource is a file of a nixpkgs package, or a URL pinned by its hash.
type NixSource struct {
	Package string `json:"package,omitempty"`
	Path    string `json:"path,omitempty"`
	URL     string `json:"url,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

// RulePreset is a preset's data of each kind; nil where it has none.
type RulePreset struct {
	GeoIP   *RuleSource `json:"geoip,omitempty"`
	Geosite *RuleSource `json:"geosite,omitempty"`
}

// DefaultRuleData is the preset of fleets that don't choose one.
const DefaultRuleData = "runetfreedom"

// rulePresetsJSON holds the presets princo knows, by name.
// internal/tools/ruledata keeps their pins up to date.
//
//go:embed rule-presets.json
var rulePresetsJSON []byte

var rulePresets = func() map[string]RulePreset {
	var out map[string]RulePreset
	if err := json.Unmarshal(rulePresetsJSON, &out); err != nil {
		panic("rule-presets.json: " + err.Error())
	}
	return out
}()

// RulePresets lists the presets' names.
func RulePresets() []string { return slices.Sorted(maps.Keys(rulePresets)) }

// ruleSource resolves the rule_data value s for kind, geoip or geosite.
func (b *builder) ruleSource(kind, s string) RuleSource {
	where := "rule_data." + kind
	s = cmp.Or(s, DefaultRuleData)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err != nil || u.Scheme != "https" || u.Host == "" {
			b.errorf("%s: %q isn't an https:// URL", where, s)
		}
		return RuleSource{URL: s}
	}
	p, ok := rulePresets[s]
	if !ok {
		b.errorf("%s: unknown preset %q (have: %s; or an https:// URL)", where, s, strings.Join(RulePresets(), ", "))
		return RuleSource{}
	}
	src := p.GeoIP
	if kind == "geosite" {
		src = p.Geosite
	}
	if src == nil {
		b.errorf("%s: preset %s has no %s data", where, s, kind)
		return RuleSource{}
	}
	out := *src
	out.Preset = s
	return out
}

func (b *builder) ruleData() {
	c := deref(b.cfg.RuleData)
	b.f.RuleData = RuleData{
		GeoIP:   b.ruleSource("geoip", c.GeoIP),
		Geosite: b.ruleSource("geosite", c.Geosite),
	}
}

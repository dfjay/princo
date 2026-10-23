package fleet

import (
	"cmp"
	"maps"
	"net/url"
	"slices"
	"strings"
)

// RuleData is where the fleet's geoip and geosite data comes from. Every
// node and client profile is built from the same, so a client sends
// traffic where the node agrees with it.
type RuleData struct {
	GeoIP   RuleSource
	Geosite RuleSource
}

// RuleSource is one kind of rule data: a preset's or a URL's.
type RuleSource struct {
	// Preset names it, or is empty for a URL of the user's.
	Preset string
	// URL is a geoip.dat or geosite.dat, or for geoip a MaxMind-format
	// .mmdb, optionally gzipped. {month} stands for the current one, as
	// 2026-10.
	URL string
}

// DefaultRuleData is the preset of fleets that don't choose one.
const DefaultRuleData = "runetfreedom"

type rulePreset struct{ geoip, geosite *RuleSource }

func datRelease(repo, file string) *RuleSource {
	return &RuleSource{URL: "https://github.com/" + repo + "/releases/latest/download/" + file}
}

// rulePresets are the rule data princo knows, by name. The NixOS module
// takes the same from nixpkgs or its own pins (nix/rule-data.nix).
var rulePresets = map[string]rulePreset{
	"runetfreedom": {
		geoip:   datRelease("runetfreedom/russia-v2ray-rules-dat", "geoip.dat"),
		geosite: datRelease("runetfreedom/russia-v2ray-rules-dat", "geosite.dat"),
	},
	"loyalsoldier": {
		geoip:   datRelease("Loyalsoldier/v2ray-rules-dat", "geoip.dat"),
		geosite: datRelease("Loyalsoldier/v2ray-rules-dat", "geosite.dat"),
	},
	"v2fly": {
		geoip:   datRelease("v2fly/geoip", "geoip.dat"),
		geosite: datRelease("v2fly/domain-list-community", "dlc.dat"),
	},
	"dbip": {
		geoip: &RuleSource{URL: "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz"},
	},
}

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
	src := p.geoip
	if kind == "geosite" {
		src = p.geosite
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

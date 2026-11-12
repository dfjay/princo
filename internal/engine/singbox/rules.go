package singbox

import (
	"maps"
	"regexp"
	"slices"
	"strconv"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

var ruleSetRe = regexp.MustCompile(regexp.QuoteMeta(engine.RuleSetDir) + `/([^/"]+)`)

// RuleSets lists the local rule sets a rendered config loads, sorted.
func (e *Engine) RuleSets(config []byte) []string {
	out := []string{}
	for _, m := range ruleSetRe.FindAllSubmatch(config, -1) {
		out = append(out, string(m[1]))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ruleSets collects the geosite/geoip rule sets rules refer to, in order of
// first use.
type ruleSets struct {
	tags []string
	seen map[string]bool
}

func (r *ruleSets) add(tag string) {
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	if !r.seen[tag] {
		r.seen[tag] = true
		r.tags = append(r.tags, tag)
	}
}

// ruleSetTag names the sing-box rule set for a geosite or geoip matcher, as
// published by SagerNet (geosite-<name>.srs, geoip-<name>.srs).
func ruleSetTag(m fleet.Matcher) string { return string(m.Kind) + "-" + m.Value }

// compileMatch turns ORed matchers into sing-box rule bodies. sing-box ANDs
// different fields of one rule (except the destination group: domains, IPs
// and rule sets), so matchers are split into one rule per field group; all
// of them get the same action.
func compileMatch(match []fleet.Matcher, sets *ruleSets) []map[string]any {
	dest := map[string]any{}
	var ports, networks, protocols []any
	appendTo := func(key string, v any) {
		list, _ := dest[key].([]any)
		dest[key] = append(list, v)
	}
	for _, m := range match {
		switch m.Kind {
		case fleet.MatchGeosite, fleet.MatchGeoIP:
			tag := ruleSetTag(m)
			sets.add(tag)
			appendTo("rule_set", tag)
		case fleet.MatchDomain:
			appendTo("domain", m.Value)
		case fleet.MatchDomainSuffix:
			appendTo("domain_suffix", m.Value)
		case fleet.MatchDomainKeyword:
			appendTo("domain_keyword", m.Value)
		case fleet.MatchIP:
			if m.Value == "private" {
				dest["ip_is_private"] = true
			} else {
				appendTo("ip_cidr", m.Value)
			}
		case fleet.MatchPort:
			p, _ := strconv.Atoi(m.Value)
			ports = append(ports, p)
		case fleet.MatchNetwork:
			networks = append(networks, m.Value)
		case fleet.MatchProtocol:
			protocols = append(protocols, m.Value)
		}
	}
	var out []map[string]any
	if len(dest) > 0 {
		out = append(out, dest)
	}
	if len(ports) > 0 {
		out = append(out, map[string]any{"port": ports})
	}
	for _, n := range networks {
		out = append(out, map[string]any{"network": n})
	}
	if len(protocols) > 0 {
		out = append(out, map[string]any{"protocol": protocols})
	}
	if len(out) == 0 {
		out = append(out, map[string]any{})
	}
	return out
}

// withAction returns the rule bodies with fields merged into each.
func withAction(bodies []map[string]any, fields map[string]any) []any {
	out := make([]any, 0, len(bodies))
	for _, body := range bodies {
		rule := maps.Clone(body)
		maps.Copy(rule, fields)
		out = append(out, rule)
	}
	return out
}

// domainOnly keeps the matchers that test the destination domain.
func domainOnly(match []fleet.Matcher) []fleet.Matcher {
	var out []fleet.Matcher
	for _, m := range match {
		if m.IsDomain() {
			out = append(out, m)
		}
	}
	return out
}

// beforeSniff keeps the matchers that hold of a connection before it is
// sniffed: all but its domain and protocol.
func beforeSniff(match []fleet.Matcher) []fleet.Matcher {
	var out []fleet.Matcher
	for _, m := range match {
		if !m.IsDomain() && m.Kind != fleet.MatchProtocol {
			out = append(out, m)
		}
	}
	return out
}

// ipOnly keeps the matchers that test destination addresses.
func ipOnly(match []fleet.Matcher) []fleet.Matcher {
	var out []fleet.Matcher
	for _, m := range match {
		if m.IsIP() {
			out = append(out, m)
		}
	}
	return out
}

// ipv6Support is how far a path carries IPv6.
type ipv6Support int

const (
	ipv6Carried ipv6Support = iota
	// ipv6Uplink is as far as the network the device is on.
	ipv6Uplink
	ipv6Missing
)

// noGlobalIPv6 matches while the default interface has no global IPv6
// address, and where sing-box can't tell.
var noGlobalIPv6 = map[string]any{
	"default_interface_address": []any{"2000::/3"},
	"invert":                    true,
}

// withoutIPv6 returns the rule taking action on what body matches and no
// rule of except does: always for ipv6Missing, under noGlobalIPv6 for
// ipv6Uplink.
func withoutIPv6(s ipv6Support, body map[string]any, except []any, action map[string]any) map[string]any {
	var all []any
	if s == ipv6Uplink {
		all = append(all, noGlobalIPv6)
	}
	all = append(all, body)
	if len(except) > 0 {
		all = append(all, map[string]any{"type": "logical", "mode": "or", "rules": except, "invert": true})
	}
	rule := body
	if len(all) > 1 {
		rule = map[string]any{"type": "logical", "mode": "and", "rules": all}
	}
	maps.Copy(rule, action)
	return rule
}

// destination compiles matchers of destinations, addresses or domains,
// into the one rule body they make; nil without any.
func destination(match []fleet.Matcher, sets *ruleSets) map[string]any {
	if len(match) == 0 {
		return nil
	}
	return compileMatch(match, sets)[0]
}

// publicOnly drops ip:private.
func publicOnly(match []fleet.Matcher) []fleet.Matcher {
	return slices.DeleteFunc(slices.Clone(match), func(m fleet.Matcher) bool {
		return m.Kind == fleet.MatchIP && m.Value == "private"
	})
}

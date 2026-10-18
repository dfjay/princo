package fleet

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MatchKind is what a Matcher tests.
type MatchKind string

const (
	MatchGeosite       MatchKind = "geosite"
	MatchGeoIP         MatchKind = "geoip"
	MatchDomain        MatchKind = "domain"
	MatchDomainSuffix  MatchKind = "domain_suffix"
	MatchDomainKeyword MatchKind = "domain_keyword"
	// MatchIP is a CIDR, or "private" for private and loopback ranges.
	MatchIP      MatchKind = "ip"
	MatchPort    MatchKind = "port"
	MatchNetwork MatchKind = "network"
)

// Matcher is one `kind:value` entry of a rule's match list.
type Matcher struct {
	Kind  MatchKind
	Value string
}

func (m Matcher) String() string { return string(m.Kind) + ":" + m.Value }

// IsDomain reports whether the matcher tests the destination domain.
func (m Matcher) IsDomain() bool {
	switch m.Kind {
	case MatchGeosite, MatchDomain, MatchDomainSuffix, MatchDomainKeyword:
		return true
	}
	return false
}

// IsIP reports whether the matcher tests the destination address.
func (m Matcher) IsIP() bool { return m.Kind == MatchGeoIP || m.Kind == MatchIP }

// ParseMatcher parses `kind:value`, e.g. geosite:category-ru or port:25.
func ParseMatcher(s string) (Matcher, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return Matcher{}, fmt.Errorf("match %q: want kind:value (e.g. geosite:category-ru)", s)
	}
	m := Matcher{Kind: MatchKind(kind), Value: value}
	switch m.Kind {
	case MatchGeosite, MatchGeoIP, MatchDomain, MatchDomainSuffix, MatchDomainKeyword:
	case MatchIP:
		if value != "private" {
			if _, err := netip.ParsePrefix(value); err != nil {
				return Matcher{}, fmt.Errorf("match %q: want ip:private or ip:<CIDR>", s)
			}
		}
	case MatchPort:
		if p, err := strconv.Atoi(value); err != nil || p < 1 || p > 65535 {
			return Matcher{}, fmt.Errorf("match %q: port must be 1-65535", s)
		}
	case MatchNetwork:
		switch value {
		case "tcp", "udp", "icmp":
		default:
			return Matcher{}, fmt.Errorf("match %q: network must be tcp, udp or icmp", s)
		}
	default:
		return Matcher{}, fmt.Errorf("match %q: unknown kind %q", s, kind)
	}
	return m, nil
}

func parseMatchers(list []string) ([]Matcher, error) {
	out := make([]Matcher, 0, len(list))
	for _, s := range list {
		m, err := ParseMatcher(s)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

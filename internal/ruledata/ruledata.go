// Package ruledata builds the rule sets of nodes and client profiles from
// the fleet's geoip and geosite data, so each engine gets the same data in
// its format: <tag>.srs for sing-box, geoip.dat and geosite.dat cut down to
// the codes the config uses for xray.
package ruledata

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Data is one fleet's geoip and geosite data, read as needed.
type Data struct {
	geoip, geosite []byte

	// The codes of geoip.dat and geosite.dat, in upper case, or of a
	// .mmdb's networks, in lower case.
	geoipIndex, geositeIndex map[string]entry
	mmdb                     map[string][]netip.Prefix
}

// New takes geoip data, a geoip.dat or a MaxMind-format .mmdb, and a
// geosite.dat, either gzipped or not. Either may be nil when no rule set
// needs it.
func New(geoip, geosite []byte) (*Data, error) {
	d := &Data{}
	var err error
	if d.geoip, err = gunzip(geoip); err != nil {
		return nil, fmt.Errorf("geoip data: %w", err)
	}
	if d.geosite, err = gunzip(geosite); err != nil {
		return nil, fmt.Errorf("geosite data: %w", err)
	}
	return d, nil
}

func gunzip(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		return data, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Needs tells which kinds of data the rule sets named are built from.
func Needs(names []string) (geoip, geosite bool) {
	for _, name := range names {
		geoip = geoip || strings.HasPrefix(name, "geoip")
		geosite = geosite || strings.HasPrefix(name, "geosite")
	}
	return geoip, geosite
}

// Files builds the rule sets named, by file name: geoip-<code>.srs and
// geosite-<code>[@<attribute>].srs for sing-box, geoip.dat and geosite.dat
// for xray, which keep the codes config uses.
func (d *Data) Files(names []string, config []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, name := range names {
		data, err := d.file(name, config)
		if err != nil {
			return nil, fmt.Errorf("rule set %s: %w", name, err)
		}
		out[name] = data
	}
	return out, nil
}

func (d *Data) file(name string, config []byte) ([]byte, error) {
	switch name {
	case "geoip.dat":
		return d.geoipDatFile(xrayCodes("geoip", config))
	case "geosite.dat":
		return d.geositeDatFile(xrayCodes("geosite", config))
	}
	tag, ok := strings.CutSuffix(name, ".srs")
	if !ok {
		return nil, fmt.Errorf("unknown kind of rule set")
	}
	if code, ok := strings.CutPrefix(tag, "geoip-"); ok {
		return d.geoipSRS(code)
	}
	if code, ok := strings.CutPrefix(tag, "geosite-"); ok {
		return d.geositeSRS(code)
	}
	return nil, fmt.Errorf("unknown kind of rule set")
}

var geoCodeRe = regexp.MustCompile(`"(geoip|geosite):([^"]+)"`)

// xrayCodes lists the codes of kind an xray config uses, in upper case:
// geosite:google@cn has attributes, geoip:!cn is negated.
func xrayCodes(kind string, config []byte) []string {
	var out []string
	for _, m := range geoCodeRe.FindAllSubmatch(config, -1) {
		if string(m[1]) == kind {
			code, _, _ := strings.Cut(strings.TrimLeft(string(m[2]), "!"), "@")
			out = append(out, strings.ToUpper(code))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// geoipNetworks is the networks of code, in upper case.
func (d *Data) geoipNetworks(code string) ([]netip.Prefix, error) {
	switch {
	case d.geoip == nil:
		return nil, fmt.Errorf("no geoip data")
	case isMMDB(d.geoip):
		if d.mmdb == nil {
			m, err := readMMDB(d.geoip)
			if err != nil {
				return nil, fmt.Errorf("geoip data: %w", err)
			}
			d.mmdb = m
		}
		if nets, ok := d.mmdb[strings.ToLower(code)]; ok {
			return nets, nil
		}
	default:
		e, err := lookup(&d.geoipIndex, d.geoip, "geoip", code)
		if err != nil {
			return nil, err
		}
		if e.body != nil {
			nets, err := geoIPEntry(e.body)
			if err != nil {
				return nil, fmt.Errorf("geoip data: %s: %w", strings.ToLower(code), err)
			}
			return nets, nil
		}
	}
	return nil, fmt.Errorf("the geoip data has no %s", strings.ToLower(code))
}

// lookup finds code's entry in data, indexing it into *index first; a
// missing code's is the zero entry.
func lookup(index *map[string]entry, data []byte, kind, code string) (entry, error) {
	if *index == nil {
		m, err := indexDat(data)
		if err != nil {
			return entry{}, fmt.Errorf("%s data: %w", kind, err)
		}
		*index = m
	}
	return (*index)[code], nil
}

func (d *Data) geoipDatFile(codes []string) ([]byte, error) {
	var out []byte
	for _, code := range codes {
		nets, err := d.geoipNetworks(code)
		if err != nil {
			return nil, err
		}
		out = appendGeoIP(out, code, nets)
	}
	return out, nil
}

func (d *Data) geoipSRS(code string) ([]byte, error) {
	code, invert := strings.CutPrefix(code, "!")
	nets, err := d.geoipNetworks(strings.ToUpper(code))
	if err != nil {
		return nil, err
	}
	cidrs := make([]string, len(nets))
	for i, p := range nets {
		cidrs[i] = p.String()
	}
	return writeSRS(option.DefaultHeadlessRule{IPCIDR: cidrs, Invert: invert})
}

func (d *Data) geositeEntryOf(code string) (entry, error) {
	if d.geosite == nil {
		return entry{}, fmt.Errorf("no geosite data")
	}
	e, err := lookup(&d.geositeIndex, d.geosite, "geosite", code)
	if err == nil && e.raw == nil {
		err = fmt.Errorf("the geosite data has no %s", strings.ToLower(code))
	}
	return e, err
}

func (d *Data) geositeDatFile(codes []string) ([]byte, error) {
	var out []byte
	for _, code := range codes {
		e, err := d.geositeEntryOf(code)
		if err != nil {
			return nil, err
		}
		out = append(out, e.raw...)
	}
	return out, nil
}

// geositeSRS builds geosite:<code>[@<attribute>...] as xray reads it: the
// domains that have every attribute named, taken literally (!cn is one).
func (d *Data) geositeSRS(tag string) ([]byte, error) {
	code, attrs, _ := strings.Cut(tag, "@")
	e, err := d.geositeEntryOf(strings.ToUpper(code))
	if err != nil {
		return nil, err
	}
	domains, err := geositeEntry(e.body)
	if err != nil {
		return nil, fmt.Errorf("geosite data: %s: %w", code, err)
	}
	var want []string
	if attrs != "" {
		want = strings.Split(strings.ToLower(attrs), "@")
	}
	var rule option.DefaultHeadlessRule
	for _, dom := range domains {
		if !containsAll(dom.attrs, want) {
			continue
		}
		// As sing-geosite converts them.
		switch dom.kind {
		case domainPlain:
			rule.DomainKeyword = append(rule.DomainKeyword, dom.value)
		case domainRegex:
			rule.DomainRegex = append(rule.DomainRegex, dom.value)
		case domainRoot:
			if strings.Contains(dom.value, ".") {
				rule.Domain = append(rule.Domain, dom.value)
			}
			rule.DomainSuffix = append(rule.DomainSuffix, "."+dom.value)
		case domainFull:
			rule.Domain = append(rule.Domain, dom.value)
		}
	}
	for _, list := range []*badoption.Listable[string]{&rule.Domain, &rule.DomainSuffix, &rule.DomainKeyword, &rule.DomainRegex} {
		*list = unique(*list)
	}
	return writeSRS(rule)
}

// unique keeps the first of each value, in order.
func unique(list []string) []string {
	seen := make(map[string]bool, len(list))
	return slices.DeleteFunc(list, func(v string) bool {
		dup := seen[v]
		seen[v] = true
		return dup
	})
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// writeSRS writes a binary sing-box rule set of rule, in the first version
// of the format, which every sing-box release reads. A rule without
// conditions, which sing-box refuses, is left out: the set matches nothing.
func writeSRS(rule option.DefaultHeadlessRule) ([]byte, error) {
	var set option.PlainRuleSet
	if rule.IsValid() {
		set.Rules = []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: rule}}
	}
	var buf bytes.Buffer
	err := srs.Write(&buf, set, C.RuleSetVersion1)
	return buf.Bytes(), err
}

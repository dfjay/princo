// Package ruledatatest writes small geoip.dat and geosite.dat files for
// tests.
package ruledatatest

import (
	"encoding/binary"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func bytesField(b []byte, num uint64, v []byte) []byte {
	b = binary.AppendUvarint(b, num<<3|2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func varintField(b []byte, num, v uint64) []byte {
	b = binary.AppendUvarint(b, num<<3)
	return binary.AppendUvarint(b, v)
}

// GeoIP is a geoip.dat of code → CIDRs, in sorted order of codes.
func GeoIP(entries map[string][]string) []byte {
	var out []byte
	for _, code := range slices.Sorted(maps.Keys(entries)) {
		body := bytesField(nil, 1, []byte(strings.ToUpper(code)))
		for _, c := range entries[code] {
			p := netip.MustParsePrefix(c)
			cidr := bytesField(nil, 1, p.Addr().AsSlice())
			cidr = varintField(cidr, 2, uint64(p.Bits()))
			body = bytesField(body, 2, cidr)
		}
		out = bytesField(out, 1, body)
	}
	return out
}

// Geosite is a geosite.dat of code → domains. A domain is written as xray
// reads one in a config: full:x, domain:x (the default), keyword:x or
// regexp:x, with @attr suffixes.
func Geosite(entries map[string][]string) []byte {
	var out []byte
	for _, code := range slices.Sorted(maps.Keys(entries)) {
		body := bytesField(nil, 1, []byte(strings.ToUpper(code)))
		for _, d := range entries[code] {
			value, attrs, _ := strings.Cut(d, "@")
			kind := uint64(2)
			for prefix, k := range map[string]uint64{"keyword:": 0, "regexp:": 1, "domain:": 2, "full:": 3} {
				if v, ok := strings.CutPrefix(value, prefix); ok {
					value, kind = v, k
				}
			}
			dom := varintField(nil, 1, kind)
			dom = bytesField(dom, 2, []byte(value))
			if attrs != "" {
				for _, a := range strings.Split(attrs, "@") {
					attr := bytesField(nil, 1, []byte(a))
					attr = varintField(attr, 2, 1)
					dom = bytesField(dom, 3, attr)
				}
			}
			body = bytesField(body, 2, dom)
		}
		out = bytesField(out, 1, body)
	}
	return out
}

// Dir is a directory with a geoip.dat and a geosite.dat that have ru and
// category-ru, as the fixture fleet uses.
func Dir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip.dat"), GeoIP(map[string][]string{
		"ru": {"5.3.0.0/16", "2a00:1fa0::/29"},
		"de": {"5.1.0.0/16"},
	}), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite.dat"), Geosite(map[string][]string{
		"category-ru": {"ru", "full:yandex.com", "keyword:vk"},
	}), 0o644))
	return dir
}

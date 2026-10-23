package ruledata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// geoip.dat and geosite.dat are protobuf lists (v2fly's routercommon):
//
//	GeoIPList   { repeated GeoIP entry = 1 }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//	CIDR        { bytes ip = 1; uint32 prefix = 2 }
//	GeoSiteList { repeated GeoSite entry = 1 }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//	Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//	Attribute   { string key = 1; oneof { bool bool_value = 2; int64 int_value = 3 } }

const (
	wireVarint = 0
	wireBytes  = 2
)

var errBadDat = errors.New("not a geodata file")

// field is one protobuf field: its number, and its value for varints or
// length-delimited ones.
type field struct {
	num    uint64
	varint uint64
	bytes  []byte
}

// fields reads the fields of a protobuf message.
func fields(b []byte, each func(field) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errBadDat
		}
		b = b[n:]
		f := field{num: key >> 3}
		switch key & 7 {
		case wireVarint:
			if f.varint, n = binary.Uvarint(b); n <= 0 {
				return errBadDat
			}
			b = b[n:]
		case wireBytes:
			size, n := binary.Uvarint(b)
			if n <= 0 || size > uint64(len(b)-n) {
				return errBadDat
			}
			f.bytes, b = b[n:n+int(size)], b[n+int(size):]
		case 1: // fixed64
			if len(b) < 8 {
				return errBadDat
			}
			b = b[8:]
		case 5: // fixed32
			if len(b) < 4 {
				return errBadDat
			}
			b = b[4:]
		default:
			return errBadDat
		}
		if err := each(f); err != nil {
			return err
		}
	}
	return nil
}

// entry is one code's entry of a geodata list.
type entry struct {
	// raw is the entry as it is in the list, field key included.
	raw  []byte
	body []byte
}

// indexDat maps each code of a geodata list, in upper case, to its entry.
// Entries start with their code, so only that much of each is read.
func indexDat(data []byte) (map[string]entry, error) {
	out := map[string]entry{}
	for len(data) > 0 {
		body, n, err := bytesField(data)
		if err != nil {
			return nil, err
		}
		code, _, err := bytesField(body)
		if err != nil || len(code) == 0 {
			return nil, errBadDat
		}
		out[strings.ToUpper(string(code))] = entry{raw: data[:n], body: body}
		data = data[n:]
	}
	return out, nil
}

// bytesField reads field 1 of b, length-delimited: its value and the bytes
// it takes.
func bytesField(b []byte) ([]byte, int, error) {
	key, k := binary.Uvarint(b)
	if k <= 0 || key != 1<<3|wireBytes {
		return nil, 0, errBadDat
	}
	size, s := binary.Uvarint(b[k:])
	if s <= 0 || size > uint64(len(b)-k-s) {
		return nil, 0, errBadDat
	}
	n := k + s + int(size)
	return b[k+s : n], n, nil
}

// geoIPEntry reads the networks of a GeoIP entry.
func geoIPEntry(body []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	err := fields(body, func(f field) error {
		switch f.num {
		case 2:
			var ip []byte
			var bits uint64
			if err := fields(f.bytes, func(c field) error {
				switch c.num {
				case 1:
					ip = c.bytes
				case 2:
					bits = c.varint
				}
				return nil
			}); err != nil {
				return err
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok || bits > uint64(addr.BitLen()) {
				return errBadDat
			}
			p, err := addr.Prefix(int(bits))
			if err != nil {
				return err
			}
			out = append(out, p)
		case 3:
			if f.varint != 0 {
				return errors.New("reverse_match entries aren't supported")
			}
		}
		return nil
	})
	return out, err
}

// Domain types of a GeoSite entry.
const (
	domainPlain = iota
	domainRegex
	domainRoot
	domainFull
)

type domain struct {
	kind  uint64
	value string
	attrs []string
}

// geositeEntry reads the domains of a GeoSite entry.
func geositeEntry(body []byte) ([]domain, error) {
	var out []domain
	err := fields(body, func(f field) error {
		if f.num != 2 {
			return nil
		}
		var d domain
		if err := fields(f.bytes, func(g field) error {
			switch g.num {
			case 1:
				d.kind = g.varint
			case 2:
				d.value = string(g.bytes)
			case 3:
				return fields(g.bytes, func(a field) error {
					if a.num == 1 {
						d.attrs = append(d.attrs, strings.ToLower(string(a.bytes)))
					}
					return nil
				})
			}
			return nil
		}); err != nil {
			return err
		}
		if d.kind > domainFull {
			return fmt.Errorf("domain %s: unknown type %d", d.value, d.kind)
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

func appendBytesField(b []byte, num uint64, v []byte) []byte {
	b = binary.AppendUvarint(b, num<<3|wireBytes)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendVarintField(b []byte, num, v uint64) []byte {
	b = binary.AppendUvarint(b, num<<3|wireVarint)
	return binary.AppendUvarint(b, v)
}

// appendGeoIP appends a geoip.dat entry for code.
func appendGeoIP(b []byte, code string, prefixes []netip.Prefix) []byte {
	body := appendBytesField(nil, 1, []byte(strings.ToUpper(code)))
	for _, p := range prefixes {
		cidr := appendBytesField(nil, 1, p.Addr().AsSlice())
		cidr = appendVarintField(cidr, 2, uint64(p.Bits()))
		body = appendBytesField(body, 2, cidr)
	}
	return appendBytesField(b, 1, body)
}

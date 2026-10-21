package deploy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var geoCodeRe = regexp.MustCompile(`"(geoip|geosite):([^"]+)"`)

// trimGeodata keeps what an xray config uses of geoip.dat or geosite.dat:
// the whole files are tens of megabytes, its codes a few hundred
// kilobytes.
func trimGeodata(file string, data, config []byte) ([]byte, error) {
	kind := strings.TrimSuffix(file, ".dat")
	var codes []string
	for _, m := range geoCodeRe.FindAllSubmatch(config, -1) {
		if string(m[1]) == kind {
			codes = append(codes, strings.ToUpper(string(m[2])))
		}
	}
	return trimDat(data, codes)
}

// trimDat keeps the entries of a geoip.dat or geosite.dat list whose code
// is one of codes. Both are protobuf lists, field 1 repeated, of messages
// whose field 1 is the code.
func trimDat(data []byte, codes []string) ([]byte, error) {
	var out []byte
	found := map[string]bool{}
	for rest := data; len(rest) > 0; {
		num, entry, n, err := lengthDelimited(rest)
		if err != nil {
			return nil, err
		}
		raw := rest[:n]
		rest = rest[n:]
		if num != 1 {
			continue
		}
		code, err := entryCode(entry)
		if err != nil {
			return nil, err
		}
		if slices.Contains(codes, strings.ToUpper(code)) {
			found[strings.ToUpper(code)] = true
			out = append(out, raw...)
		}
	}
	for _, c := range codes {
		if !found[c] {
			return nil, fmt.Errorf("it has no %s", strings.ToLower(c))
		}
	}
	return out, nil
}

// entryCode is the string in an entry's field 1.
func entryCode(entry []byte) (string, error) {
	for len(entry) > 0 {
		key, n := binary.Uvarint(entry)
		if n <= 0 {
			return "", errBadDat
		}
		if key>>3 == 1 && key&7 == 2 {
			_, code, _, err := lengthDelimited(entry)
			return string(code), err
		}
		skip, err := fieldLen(entry[n:], key&7)
		if err != nil {
			return "", err
		}
		if n+skip > len(entry) {
			return "", errBadDat
		}
		entry = entry[n+skip:]
	}
	return "", errBadDat
}

var errBadDat = errors.New("not a geodata file")

// lengthDelimited reads a length-delimited field: its number, its value,
// and the bytes it takes.
func lengthDelimited(b []byte) (num uint64, value []byte, n int, err error) {
	key, k := binary.Uvarint(b)
	if k <= 0 || key&7 != 2 {
		return 0, nil, 0, errBadDat
	}
	size, s := binary.Uvarint(b[k:])
	if s <= 0 || size > uint64(len(b)-k-s) {
		return 0, nil, 0, errBadDat
	}
	n = k + s + int(size)
	return key >> 3, b[k+s : n], n, nil
}

// fieldLen is how many bytes a value of wire type typ takes in b.
func fieldLen(b []byte, typ uint64) (int, error) {
	switch typ {
	case 0:
		_, n := binary.Uvarint(b)
		if n <= 0 {
			return 0, errBadDat
		}
		return n, nil
	case 1:
		return 8, nil
	case 2:
		size, n := binary.Uvarint(b)
		if n <= 0 || size > uint64(len(b)-n) {
			return 0, errBadDat
		}
		return n + int(size), nil
	case 5:
		return 4, nil
	default:
		return 0, errBadDat
	}
}

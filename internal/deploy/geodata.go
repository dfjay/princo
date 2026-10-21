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

// trimGeodata keeps the codes an xray config uses of geoip.dat or
// geosite.dat. Both are protobuf lists of entries that start with their
// code.
func trimGeodata(file string, data, config []byte) ([]byte, error) {
	kind := strings.TrimSuffix(file, ".dat")
	var missing []string
	for _, m := range geoCodeRe.FindAllSubmatch(config, -1) {
		if string(m[1]) == kind {
			// geosite:google@cn has attributes, geoip:!cn is negated.
			code, _, _ := strings.Cut(strings.TrimLeft(string(m[2]), "!"), "@")
			missing = append(missing, strings.ToUpper(code))
		}
	}
	var out []byte
	for len(data) > 0 {
		entry, n, err := bytesField(data)
		if err != nil {
			return nil, err
		}
		code, _, err := bytesField(entry)
		if err != nil {
			return nil, err
		}
		if c := strings.ToUpper(string(code)); slices.Contains(missing, c) {
			out = append(out, data[:n]...)
			missing = slices.DeleteFunc(missing, func(m string) bool { return m == c })
		}
		data = data[n:]
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("it has no %s", strings.ToLower(missing[0]))
	}
	return out, nil
}

var errBadDat = errors.New("not a geodata file")

// bytesField reads field 1 of b, length-delimited: its value and the bytes
// it takes.
func bytesField(b []byte) ([]byte, int, error) {
	key, k := binary.Uvarint(b)
	if k <= 0 || key != 1<<3|2 {
		return nil, 0, errBadDat
	}
	size, s := binary.Uvarint(b[k:])
	if s <= 0 || size > uint64(len(b)-k-s) {
		return nil, 0, errBadDat
	}
	n := k + s + int(size)
	return b[k+s : n], n, nil
}

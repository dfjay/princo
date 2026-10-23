package ruledata

import (
	"bytes"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// mmdbMarker starts the metadata section of a MaxMind DB.
var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

func isMMDB(data []byte) bool { return bytes.Contains(data, mmdbMarker) }

// readMMDB groups the networks of a MaxMind-format country database by
// country code, in lower case. A network is where it's located, else
// where it's registered; networks with neither are left out.
func readMMDB(data []byte) (map[string][]netip.Prefix, error) {
	db, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, err
	}
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}
	out := map[string][]netip.Prefix{}
	for r := range db.Networks() {
		record.Country.ISOCode, record.RegisteredCountry.ISOCode = "", ""
		if err := r.Decode(&record); err != nil {
			return nil, err
		}
		code := strings.ToLower(record.Country.ISOCode)
		if code == "" {
			code = strings.ToLower(record.RegisteredCountry.ISOCode)
		}
		if code != "" {
			out[code] = append(out[code], r.Prefix())
		}
	}
	return out, nil
}

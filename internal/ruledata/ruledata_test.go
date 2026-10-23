package ruledata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/ruledata/ruledatatest"
)

var update = flag.Bool("update", false, "rewrite testdata/ruledata")

var (
	geoipDat = ruledatatest.GeoIP(map[string][]string{
		"ru": {"5.3.0.0/16", "2a00:1fa0::/29"},
		"de": {"5.1.0.0/16"},
	})
	geositeDat = ruledatatest.Geosite(map[string][]string{
		"category-ru": {"ru", "full:yandex.com", "keyword:vkontakte", "regexp:^ya\\.", "vk.com@ads"},
		"google":      {"google.com", "google.cn@cn", "google.com.hk@!cn@ads"},
	})
)

// rule reads back the one rule of a sing-box rule set.
func rule(t *testing.T, data []byte) option.DefaultHeadlessRule {
	t.Helper()
	rs, err := srs.Read(bytes.NewReader(data), true)
	require.NoError(t, err)
	require.Len(t, rs.Options.Rules, 1)
	return rs.Options.Rules[0].DefaultOptions
}

func files(t *testing.T, geoip, geosite []byte, names []string, config string) map[string][]byte {
	t.Helper()
	d, err := New(geoip, geosite)
	require.NoError(t, err)
	out, err := d.Files(names, []byte(config))
	require.NoError(t, err)
	return out
}

func TestGeoIPSRS(t *testing.T) {
	out := files(t, geoipDat, nil, []string{"geoip-ru.srs", "geoip-!de.srs"}, "")
	ru := rule(t, out["geoip-ru.srs"])
	require.Equal(t, []string{"5.3.0.0/16", "2a00:1fa0::/29"}, []string(ru.IPCIDR))
	require.False(t, ru.Invert)
	de := rule(t, out["geoip-!de.srs"])
	require.Equal(t, []string{"5.1.0.0/16"}, []string(de.IPCIDR))
	require.True(t, de.Invert)
}

func TestGeositeSRS(t *testing.T) {
	out := files(t, nil, geositeDat, []string{"geosite-category-ru.srs", "geosite-google@cn.srs", "geosite-google@!cn@ads.srs", "geosite-google@cn@ads.srs"}, "")
	ru := rule(t, out["geosite-category-ru.srs"])
	// A bare TLD only as a suffix, as sing-geosite has it.
	for host, want := range map[string]bool{
		"mail.ru":         true,
		"yandex.com":      true,
		"mail.yandex.com": false, // full:
		"vk.com":          true,
		"m.vk.com":        true,
		"vk.org":          false,
	} {
		require.Equal(t, want, ru.DomainMatcher.Match(host), host)
	}
	require.Equal(t, []string{"vkontakte"}, []string(ru.DomainKeyword))
	require.Equal(t, []string{"^ya\\."}, []string(ru.DomainRegex))

	cn := rule(t, out["geosite-google@cn.srs"]).DomainMatcher
	require.True(t, cn.Match("google.cn"))
	require.False(t, cn.Match("google.com"))
	// As xray reads it: !cn is an attribute of its own, and attributes AND.
	notCN := rule(t, out["geosite-google@!cn@ads.srs"]).DomainMatcher
	require.True(t, notCN.Match("google.com.hk"))
	require.False(t, notCN.Match("google.com"))

	rs, err := srs.Read(bytes.NewReader(out["geosite-google@cn@ads.srs"]), true)
	require.NoError(t, err)
	require.Empty(t, rs.Options.Rules, "nothing selected: no rule, which sing-box would refuse")
}

func TestXrayDat(t *testing.T) {
	config := `{"ip": ["geoip:!ru"], "domain": ["geosite:google@cn"]}`
	out := files(t, geoipDat, geositeDat, []string{"geoip.dat", "geosite.dat"}, config)

	d, err := New(out["geoip.dat"], out["geosite.dat"])
	require.NoError(t, err)
	_, err = d.geoipNetworks("RU")
	require.NoError(t, err)
	require.Equal(t, []string{"RU"}, slices.Collect(maps.Keys(d.geoipIndex)), "only what the config uses")
	_, err = d.geositeEntryOf("GOOGLE")
	require.NoError(t, err)
	_, err = d.geositeEntryOf("CATEGORY-RU")
	require.ErrorContains(t, err, "has no category-ru")
}

func TestMissing(t *testing.T) {
	d, err := New(geoipDat, nil)
	require.NoError(t, err)
	_, err = d.Files([]string{"geoip-fr.srs"}, nil)
	require.EqualError(t, err, "rule set geoip-fr.srs: the geoip data has no fr")
	_, err = d.Files([]string{"geosite-google.srs"}, nil)
	require.EqualError(t, err, "rule set geosite-google.srs: no geosite data")
	_, err = d.Files([]string{"rules.txt"}, nil)
	require.ErrorContains(t, err, "unknown kind of rule set")

	d, err = New([]byte("<html>"), nil)
	require.NoError(t, err)
	_, err = d.Files([]string{"geoip-ru.srs"}, nil)
	require.ErrorContains(t, err, "not a geodata file")
}

// mmdb is a country database where 5.3.0.0/16 is located in Russia,
// 5.1.0.0/16 only registered in Germany, and 5.9.0.0/16 neither.
func mmdb(t *testing.T) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "test", IPVersion: 6})
	require.NoError(t, err)
	insert := func(cidr string, record mmdbtype.Map) {
		_, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		require.NoError(t, tree.Insert(n, record))
	}
	insert("5.3.0.0/16", mmdbtype.Map{
		"country":            mmdbtype.Map{"iso_code": mmdbtype.String("RU")},
		"registered_country": mmdbtype.Map{"iso_code": mmdbtype.String("NL")},
	})
	insert("5.1.0.0/16", mmdbtype.Map{"registered_country": mmdbtype.Map{"iso_code": mmdbtype.String("DE")}})
	insert("5.9.0.0/16", mmdbtype.Map{"city": mmdbtype.String("nowhere")})
	var buf bytes.Buffer
	_, err = tree.WriteTo(&buf)
	require.NoError(t, err)
	return buf.Bytes()
}

func TestMMDB(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, err := w.Write(mmdb(t))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	out := files(t, gz.Bytes(), nil, []string{"geoip-ru.srs", "geoip-de.srs", "geoip.dat"}, `["geoip:ru"]`)
	require.Equal(t, []string{"5.3.0.0/16"}, []string(rule(t, out["geoip-ru.srs"]).IPCIDR), "where it's located, not registered")
	require.Equal(t, []string{"5.1.0.0/16"}, []string(rule(t, out["geoip-de.srs"]).IPCIDR), "where it's registered, lacking a location")

	d, err := New(out["geoip.dat"], nil)
	require.NoError(t, err)
	nets, err := d.geoipNetworks("RU")
	require.NoError(t, err)
	require.Equal(t, "[5.3.0.0/16]", fmt.Sprint(nets), "xray gets the same")
}

func TestFetch(t *testing.T) {
	data := []byte("geoip")
	sum := sha256.Sum256(data)
	published := hex.EncodeToString(sum[:]) + "  geoip.dat\n"
	served := map[string][]byte{
		"https://x/geoip.dat":           data,
		"https://x/geoip.dat.sha256sum": []byte(published),
		"https://x/2026-09.mmdb":        []byte("september"),
		"https://x/q.dat?v=1":           data,
		"https://x/q.dat.sha256sum?v=1": []byte(hex.EncodeToString(make([]byte, 32))),
	}
	get := func(_ context.Context, url string) ([]byte, error) {
		if b, ok := served[url]; ok {
			return b, nil
		}
		return nil, fmt.Errorf("404 %s: %w", url, fs.ErrNotExist)
	}
	ctx := t.Context()
	now := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)

	src := fleet.RuleSource{URL: "https://x/geoip.dat"}
	got, err := Fetch(ctx, get, src, now)
	require.NoError(t, err)
	require.Equal(t, data, got)
	served["https://x/geoip.dat.sha256sum"] = []byte(strings.ToUpper(published))
	_, err = Fetch(ctx, get, src, now)
	require.NoError(t, err)

	served["https://x/geoip.dat.sha256sum"] = []byte(hex.EncodeToString(make([]byte, 32)))
	_, err = Fetch(ctx, get, src, now)
	require.ErrorContains(t, err, "as published")

	served["https://x/geoip.dat.sha256sum"] = []byte("<html>")
	_, err = Fetch(ctx, get, src, now)
	require.NoError(t, err, "a page isn't a SHA-256")
	delete(served, "https://x/geoip.dat.sha256sum")
	_, err = Fetch(ctx, get, src, now)
	require.NoError(t, err, "nothing published")

	_, err = Fetch(ctx, get, fleet.RuleSource{URL: "https://x/q.dat?v=1"}, now)
	require.ErrorContains(t, err, "as published", "the sum beside the path, not the query")

	got, err = Fetch(ctx, get, fleet.RuleSource{URL: "https://x/{month}.mmdb"}, now)
	require.NoError(t, err)
	require.Equal(t, []byte("september"), got, "last month's while this one's isn't out")
	served["https://x/2026-10.mmdb"] = []byte("october")
	served["https://x/2026-10.mmdb.sha256sum"] = []byte(hex.EncodeToString(make([]byte, 32)))
	_, err = Fetch(ctx, get, fleet.RuleSource{URL: "https://x/{month}.mmdb"}, now)
	require.ErrorContains(t, err, "as published", "no falling back past a bad download")
	delete(served, "https://x/2026-10.mmdb.sha256sum")
	got, err = Fetch(ctx, get, fleet.RuleSource{URL: "https://x/{month}.mmdb"}, now)
	require.NoError(t, err)
	require.Equal(t, []byte("october"), got)
}

func TestReadDir(t *testing.T) {
	dir := t.TempDir()
	geoip, geosite, err := ReadDir(dir)
	require.NoError(t, err)
	require.Nil(t, geoip)
	require.Nil(t, geosite)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip"), []byte("mmdb"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite.dat"), []byte("dat"), 0o644))
	geoip, geosite, err = ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, []byte("mmdb"), geoip)
	require.Equal(t, []byte("dat"), geosite)
}

// TestFixture checks that testdata/ruledata, the NixOS test's rule data, is
// ruledatatest.Dir's; -update rewrites it.
func TestFixture(t *testing.T) {
	src := ruledatatest.Dir(t)
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		want, err := os.ReadFile(filepath.Join(src, name))
		require.NoError(t, err)
		path := filepath.Join("../../testdata/ruledata", name)
		if *update {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			require.NoError(t, os.WriteFile(path, want, 0o644))
		}
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, want, got, "run with -update")
	}
}

// Protocol buffers may write an entry's fields in any order.
func TestIndexDat_CodeNotFirst(t *testing.T) {
	cidr := appendVarintField(appendBytesField(nil, 1, []byte{5, 3, 0, 0}), 2, 16)
	body := appendBytesField(appendBytesField(nil, 2, cidr), 1, []byte("RU"))
	d, err := New(appendBytesField(nil, 1, body), nil)
	require.NoError(t, err)
	nets, err := d.geoipNetworks("RU")
	require.NoError(t, err)
	require.Equal(t, "[5.3.0.0/16]", fmt.Sprint(nets))
}

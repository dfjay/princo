package ruledata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dfjay/princo/internal/fleet"
)

// Get GETs a URL. What the server doesn't have is fs.ErrNotExist.
type Get func(ctx context.Context, url string) ([]byte, error)

// Fetch downloads src's latest data, which must match the SHA-256 published
// at <URL>.sha256sum where there is one. A {month} in its URL is the current
// month's, or the last one's while the current isn't published yet.
func Fetch(ctx context.Context, get Get, src fleet.RuleSource, now time.Time) ([]byte, error) {
	if !strings.Contains(src.URL, "{month}") {
		return fetch(ctx, get, src.URL)
	}
	month := func(t time.Time) string { return strings.ReplaceAll(src.URL, "{month}", t.Format("2006-01")) }
	data, err := fetch(ctx, get, month(now.UTC()))
	if errors.Is(err, fs.ErrNotExist) {
		return fetch(ctx, get, month(now.UTC().AddDate(0, 0, -now.UTC().Day())))
	}
	return data, err
}

func fetch(ctx context.Context, get Get, rawURL string) ([]byte, error) {
	data, err := get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	u.Path += ".sha256sum"
	if u.RawPath != "" {
		u.RawPath += ".sha256sum"
	}
	published, err := get(ctx, u.String())
	if errors.Is(err, fs.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return nil, err
	}
	want, _, _ := strings.Cut(strings.TrimSpace(string(published)), " ")
	// Some sites answer every path with a page of their own.
	if !sha256Re.MatchString(want) {
		return data, nil
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != strings.ToLower(want) {
		return nil, fmt.Errorf("SHA-256 of %s is %s, not %s as published; was it updated while downloading?", rawURL, got, want)
	}
	return data, nil
}

var sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// ReadDir reads the geoip data, geoip.dat or geoip.mmdb (maybe gzipped), and
// geosite.dat from dir, or files named just geoip and geosite, whatever their
// format; what isn't there is nil.
func ReadDir(dir string) (geoip, geosite []byte, err error) {
	read := func(names ...string) ([]byte, error) {
		for _, name := range names {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if !errors.Is(err, os.ErrNotExist) {
				return data, err
			}
		}
		return nil, nil
	}
	if geoip, err = read("geoip.dat", "geoip.mmdb", "geoip.mmdb.gz", "geoip"); err != nil {
		return nil, nil, err
	}
	if geosite, err = read("geosite.dat", "geosite"); err != nil {
		return nil, nil, err
	}
	return geoip, geosite, nil
}

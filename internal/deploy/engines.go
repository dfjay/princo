package deploy

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dfjay/princo/internal/engine"
)

// engineSpec is how a Debian host runs an engine, like nix/engines.nix.
type engineSpec struct {
	command func(config, stateDir string) []string
	check   func(config string) []string
	// environment is the engine's, as NAME=value.
	environment []string
	// reloads tells whether SIGHUP reloads the config.
	reloads bool
	// repo has pkg; nil when the distribution does.
	repo *aptRepo
	pkg  string
	// pkgUnit comes with pkg; princo.service replaces it.
	pkgUnit string
	// binary is the engine when it has no package.
	binary       *release
	ruleSetURL   func(file string) string
	ruleSetMagic []byte
	// trim cuts a rule set down to what the config uses.
	trim func(file string, data, config []byte) ([]byte, error)
}

// release is an engine's executable, in a zip per Debian architecture.
type release struct {
	Path    string
	Version string
	Zips    map[string]download
	// Member is the executable's name in the zip.
	Member string
}

type download struct {
	URL    string
	SHA256 string
}

type aptRepo struct {
	Name    string
	Key     string
	Sources string
}

// sagernetKey is https://sing-box.app/gpg.key, fingerprint
// 2C31 7FBD 5D88 6B4E 89BA E8DA 6D91 5217 2A2B 2F0C.
//
//go:embed keys/sagernet.asc
var sagernetKey string

var engines = map[string]engineSpec{
	"sing-box": {
		command: func(config, stateDir string) []string {
			return []string{"/usr/bin/sing-box", "-D", stateDir, "-c", config, "run"}
		},
		check: func(config string) []string {
			return []string{"/usr/bin/sing-box", "check", "-c", config}
		},
		reloads: true,
		repo: &aptRepo{
			Name: "sagernet",
			Key:  sagernetKey,
			Sources: `Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
`,
		},
		pkg:     "sing-box",
		pkgUnit: "sing-box.service",
		ruleSetURL: func(file string) string {
			repo := "sing-geosite"
			if strings.HasPrefix(file, "geoip-") {
				repo = "sing-geoip"
			}
			return "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + file
		},
		ruleSetMagic: []byte("SRS"),
	},
	"xray": {
		command: func(config, _ string) []string {
			return []string{xrayBin, "run", "-c", config}
		},
		check: func(config string) []string {
			return []string{"/usr/bin/env", "XRAY_LOCATION_ASSET=" + engine.RuleSetDir, xrayBin, "run", "-test", "-c", config}
		},
		environment: []string{"XRAY_LOCATION_ASSET=" + engine.RuleSetDir},
		binary:      xrayRelease,
		ruleSetURL: func(file string) string {
			return "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/" + file
		},
		// A protobuf list: field 1, length-delimited.
		ruleSetMagic: []byte{0x0a},
		trim:         trimGeodata,
	},
}

// extract checks data, downloaded from z, and returns the executable in it.
func (b *release) extract(z download, data []byte) ([]byte, error) {
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != z.SHA256 {
		return nil, fmt.Errorf("%s doesn't match its pinned SHA-256", z.URL)
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", z.URL, err)
	}
	f, err := r.Open(b.Member)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", z.URL, err)
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

const xrayBin = "/usr/local/lib/princo/xray"

// xrayRelease is xray.MinVersion. XTLS signs no releases, so the
// checksums are pinned.
var xrayRelease = &release{
	Path:    xrayBin,
	Version: "26.3.27",
	Zips: map[string]download{
		"amd64": {
			URL:    "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip",
			SHA256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
		},
		"arm64": {
			URL:    "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip",
			SHA256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
		},
	},
	Member: "xray",
}

// RuleSets reads each of the engine's rule sets from dir, or downloads the
// latest when dir is empty, keeping what config uses.
func RuleSets(ctx context.Context, client *http.Client, dir, engineName string, files []string, config []byte) (map[string][]byte, error) {
	e, ok := engines[engineName]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s yet", engineName)
	}
	out := map[string][]byte{}
	for _, f := range files {
		src := filepath.Join(dir, f)
		var data []byte
		var err error
		if dir == "" {
			src = e.ruleSetURL(f)
			data, err = Fetch(ctx, client, src)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			return nil, fmt.Errorf("rule set %s: %w", f, err)
		}
		if !bytes.HasPrefix(data, e.ruleSetMagic) {
			return nil, fmt.Errorf("rule set %s: %s isn't a %s rule set", f, src, engineName)
		}
		if e.trim != nil {
			if data, err = e.trim(f, data, config); err != nil {
				return nil, fmt.Errorf("rule set %s: %s: %w", f, src, err)
			}
		}
		out[f] = data
	}
	return out, nil
}

// Fetch GETs url.
func Fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

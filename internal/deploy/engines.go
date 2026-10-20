package deploy

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// engineSpec is how a Debian host runs an engine, like nix/engines.nix.
type engineSpec struct {
	command func(config, stateDir string) []string
	check   func(config string) []string
	// reloads tells whether SIGHUP reloads the config.
	reloads bool
	// repo has pkg; nil when the distribution does.
	repo *aptRepo
	pkg  string
	// pkgUnit comes with pkg; princo.service replaces it.
	pkgUnit      string
	ruleSetURL   func(file string) string
	ruleSetMagic []byte
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
}

// RuleSets reads each of the engine's rule sets from dir, or downloads the
// latest when dir is empty.
func RuleSets(ctx context.Context, client *http.Client, dir, engineName string, files []string) (map[string][]byte, error) {
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
			data, err = fetch(ctx, client, src)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			return nil, fmt.Errorf("rule set %s: %w", f, err)
		}
		if !bytes.HasPrefix(data, e.ruleSetMagic) {
			return nil, fmt.Errorf("rule set %s: %s isn't a %s rule set", f, src, engineName)
		}
		out[f] = data
	}
	return out, nil
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
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

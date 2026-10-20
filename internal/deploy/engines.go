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

// engineSpec is what a deploy needs to know about running an engine on a
// Debian host, like nix/engines.nix for NixOS.
type engineSpec struct {
	// command runs the engine on config, keeping its state in stateDir.
	command func(config, stateDir string) []string
	// check validates config before the engine restarts on it.
	check func(config string) []string
	// reloads tells whether SIGHUP reloads the config.
	reloads bool
	// repo is the apt repository of pkg, nil when the distribution has it.
	repo *aptRepo
	pkg  string
	// pkgUnit is the systemd unit pkg brings, which princo.service replaces.
	pkgUnit string
	// ruleSetURL is where a file of the plan's rule sets is downloaded.
	ruleSetURL func(file string) string
	// ruleSetMagic starts every rule set file.
	ruleSetMagic []byte
}

// aptRepo is an apt repository to add, in deb822 form, signed by Key.
type aptRepo struct {
	Name    string
	Key     string
	Sources string
}

// sagernetKey signs SagerNet's apt repository, from
// https://sing-box.app/gpg.key: fingerprint
// 2C31 7FBD 5D88 6B4E 89BA E8DA 6D91 5217 2A2B 2F0C.
//
//go:embed keys/sagernet.asc
var sagernetKey string

var engines = map[string]engineSpec{
	"sing-box": {
		command: func(config, stateDir string) []string {
			// Where SagerNet's Debian package installs it.
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

// FetchRuleSets downloads the latest of each rule set an engine's node
// loads.
func FetchRuleSets(ctx context.Context, client *http.Client, engineName string, files []string) (map[string][]byte, error) {
	e, ok := engines[engineName]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s yet", engineName)
	}
	out := map[string][]byte{}
	for _, f := range files {
		data, err := fetch(ctx, client, e.ruleSetURL(f))
		if err != nil {
			return nil, fmt.Errorf("rule set %s: %w", f, err)
		}
		if !bytes.HasPrefix(data, e.ruleSetMagic) {
			return nil, fmt.Errorf("rule set %s: %s isn't a %s rule set", f, e.ruleSetURL(f), engineName)
		}
		out[f] = data
	}
	return out, nil
}

// ReadRuleSets reads each rule set from dir instead, e.g. to pin them.
func ReadRuleSets(dir, engineName string, files []string) (map[string][]byte, error) {
	e, ok := engines[engineName]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s yet", engineName)
	}
	out := map[string][]byte{}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, fmt.Errorf("rule set %s: %w", f, err)
		}
		if !bytes.HasPrefix(data, e.ruleSetMagic) {
			return nil, fmt.Errorf("rule set %s: %s isn't a %s rule set", f, filepath.Join(dir, f), engineName)
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

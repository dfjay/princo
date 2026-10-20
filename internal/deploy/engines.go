package deploy

import (
	"bytes"
	"context"
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
	// reloads tells whether SIGHUP reloads the config.
	reloads bool
	// ruleSetURL is where a file of the plan's rule sets is downloaded.
	ruleSetURL func(file string) string
	// ruleSetMagic starts every rule set file.
	ruleSetMagic []byte
}

var engines = map[string]engineSpec{
	"sing-box": {
		command: func(config, stateDir string) []string {
			// Where SagerNet's Debian package installs it.
			return []string{"/usr/bin/sing-box", "-D", stateDir, "-c", config, "run"}
		},
		reloads: true,
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

// Command ruledata pins the latest releases of the rule data presets that
// nixpkgs doesn't package, for the NixOS module:
//
//	ruledata pin <file>   update the pinned presets of file (internal/fleet/rule-presets.json)
//
// GITHUB_TOKEN, when set, authenticates its GitHub API requests.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dfjay/princo/internal/deploy"
	"github.com/dfjay/princo/internal/fleet"
)

// latestRe matches a GitHub release asset's URL in its latest release.
var latestRe = regexp.MustCompile(`^https://github\.com/([^/]+/[^/]+)/releases/latest/download/([^/]+)$`)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "pin" {
		fmt.Fprintln(os.Stderr, "usage: ruledata pin <file>")
		os.Exit(2)
	}
	if err := pin(context.Background(), os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "ruledata:", err)
		os.Exit(1)
	}
}

// pin points each source pinned by URL at the latest release of its URL's.
func pin(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var presets map[string]fleet.RulePreset
	if err := json.Unmarshal(data, &presets); err != nil {
		return err
	}
	client := &http.Client{Timeout: time.Minute}
	tags := map[string]string{}
	for name, p := range presets {
		for _, src := range []*fleet.RuleSource{p.GeoIP, p.Geosite} {
			if src == nil || src.Nix == nil || src.Nix.URL == "" {
				continue
			}
			m := latestRe.FindStringSubmatch(src.URL)
			if m == nil {
				return fmt.Errorf("%s: %s isn't a GitHub release asset", name, src.URL)
			}
			repo, file := m[1], m[2]
			if tags[repo] == "" {
				if tags[repo], err = latestTag(ctx, client, repo); err != nil {
					return err
				}
			}
			url := "https://github.com/" + repo + "/releases/download/" + tags[repo] + "/" + file
			hash, err := publishedHash(ctx, client, url)
			if err != nil {
				return err
			}
			src.Nix.URL, src.Nix.Hash = url, hash
		}
	}
	out, err := json.Marshal(presets, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func latestTag(ctx context.Context, client *http.Client, repo string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", req.URL, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var release struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return "", err
	}
	return release.Tag, nil
}

// publishedHash is the SRI hash of the SHA-256 published beside url, which
// saves downloading the file.
func publishedHash(ctx context.Context, client *http.Client, url string) (string, error) {
	sums, err := deploy.Fetch(ctx, client, url+".sha256sum")
	if err != nil {
		return "", err
	}
	hexSum, _, _ := strings.Cut(strings.TrimSpace(string(sums)), " ")
	sum, err := hex.DecodeString(hexSum)
	if err != nil || len(sum) != sha256.Size {
		return "", fmt.Errorf("%s.sha256sum: not a SHA-256", url)
	}
	return "sha256-" + base64.StdEncoding.EncodeToString(sum), nil
}

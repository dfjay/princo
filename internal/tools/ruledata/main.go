// Command ruledata pins the latest releases of the rule data presets that
// nixpkgs doesn't package, for the NixOS module:
//
//	ruledata pin <file>   write their URLs and hashes to file (nix/rule-data.json)
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dfjay/princo/internal/deploy"
)

// pinned are the presets' GitHub repositories.
var pinned = map[string]string{
	"runetfreedom": "runetfreedom/russia-v2ray-rules-dat",
}

type file struct {
	URL  string `json:"url"`
	Hash string `json:"hash"`
}

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

func pin(ctx context.Context, path string) error {
	client := &http.Client{Timeout: time.Minute}
	out := map[string]map[string]file{}
	for preset, repo := range pinned {
		data, err := deploy.Fetch(ctx, client, "https://api.github.com/repos/"+repo+"/releases/latest")
		if err != nil {
			return err
		}
		var release struct {
			Tag string `json:"tag_name"`
		}
		if err := json.Unmarshal(data, &release); err != nil {
			return err
		}
		out[preset] = map[string]file{}
		for kind, name := range map[string]string{"geoip": "geoip.dat", "geosite": "geosite.dat"} {
			url := "https://github.com/" + repo + "/releases/download/" + release.Tag + "/" + name
			// The published SHA-256 saves downloading the file.
			sums, err := deploy.Fetch(ctx, client, url+".sha256sum")
			if err != nil {
				return err
			}
			hexSum, _, _ := strings.Cut(strings.TrimSpace(string(sums)), " ")
			sum, err := hex.DecodeString(hexSum)
			if err != nil || len(sum) != sha256.Size {
				return fmt.Errorf("%s.sha256sum: not a SHA-256", url)
			}
			out[preset][kind] = file{URL: url, Hash: "sha256-" + base64.StdEncoding.EncodeToString(sum)}
		}
	}
	data, err := json.Marshal(out, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

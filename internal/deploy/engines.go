package deploy

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/engine"
)

// engineSpec is how a Debian host runs an engine, like nix/engines.nix.
type engineSpec struct {
	// version is the release princo deploy installs.
	version string
	release release
	command func(bin, config, stateDir string) []string
	check   func(bin, config string) []string
	// environment is the engine's, as NAME=value.
	environment []string
	// reloads tells whether SIGHUP reloads the config.
	reloads      bool
	ruleSetURL   func(file string) string
	ruleSetMagic []byte
	// trim cuts a rule set down to what the config uses.
	trim func(file string, data, config []byte) ([]byte, error)
}

// engineRoot holds a directory per engine release. The unit runs its
// release's, so a rollback runs the old release again.
const engineRoot = "/usr/local/lib/princo"

// dir is where the engine's release goes on the host.
func (e engineSpec) dir() string {
	return path.Join(engineRoot, e.release.Files[0]+"-"+e.version)
}

// bin is the engine's executable.
func (e engineSpec) bin() string {
	return path.Join(e.dir(), e.release.Files[0])
}

// release is an engine's archive per Debian architecture, pinned by
// checksum: neither SagerNet nor XTLS sign theirs.
type release struct {
	// URL is an archive's, with {version} and {arch} to fill in.
	URL string
	// Arch names Debian architectures as the archives do, where they differ.
	Arch map[string]string
	// SHA256 is each Debian architecture's archive's.
	SHA256 map[string]string
	// Files are what the engine needs of an archive, first its executable,
	// named as the engine.
	Files []string
}

type download struct {
	URL    string
	SHA256 string
}

func (r release) url(version, arch string) string {
	return strings.NewReplacer("{version}", version, "{arch}", cmp.Or(r.Arch[arch], arch)).Replace(r.URL)
}

// archive is the engine's release for a Debian architecture.
func (e engineSpec) archive(arch string) (download, bool) {
	sum, ok := e.release.SHA256[arch]
	return download{URL: e.release.url(e.version, arch), SHA256: sum}, ok
}

var engines = map[string]engineSpec{
	"sing-box": {
		version: "1.14.3",
		release: release{
			URL: "https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}.tar.gz",
			SHA256: map[string]string{
				"amd64": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
				"arm64": "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
			},
			Files: []string{"sing-box", "libcronet.so"},
		},
		command: func(bin, config, stateDir string) []string {
			return []string{bin, "-D", stateDir, "-c", config, "run"}
		},
		check: func(bin, config string) []string {
			return []string{bin, "check", "-c", config}
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
	"xray": {
		version: "26.10.21",
		release: release{
			URL:  "https://github.com/XTLS/Xray-core/releases/download/v{version}/Xray-linux-{arch}.zip",
			Arch: map[string]string{"amd64": "64", "arm64": "arm64-v8a"},
			SHA256: map[string]string{
				"amd64": "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978",
				"arm64": "d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c",
			},
			Files: []string{"xray"},
		},
		command: func(bin, config, _ string) []string {
			return []string{bin, "run", "-c", config}
		},
		check: func(bin, config string) []string {
			return []string{"/usr/bin/env", "XRAY_LOCATION_ASSET=" + engine.RuleSetDir, bin, "run", "-test", "-c", config}
		},
		environment: []string{"XRAY_LOCATION_ASSET=" + engine.RuleSetDir},
		ruleSetURL: func(file string) string {
			return "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/" + file
		},
		// A protobuf list: field 1, length-delimited.
		ruleSetMagic: []byte{0x0a},
		trim:         trimGeodata,
	},
}

// extract checks data, downloaded from d, and returns r's files in it as
// a tar archive.
func (r release) extract(d download, data []byte) ([]byte, error) {
	files, err := d.unpack(data, func(name string) bool { return slices.Contains(r.Files, name) })
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, name := range r.Files {
		data, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("%s has no %s", d.URL, name)
		}
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// unpack checks data, d's download, and reads the files want picks out
// of it by name.
func (d download) unpack(data []byte, want func(name string) bool) (map[string][]byte, error) {
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != d.SHA256 {
		return nil, fmt.Errorf("%s doesn't match its pinned SHA-256", d.URL)
	}
	files, err := readArchive(d.URL, data, want)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", d.URL, err)
	}
	return files, nil
}

// readArchive reads the files want picks out of a .zip or .tar.gz, by name.
func readArchive(url string, data []byte, want func(name string) bool) (map[string][]byte, error) {
	files := map[string][]byte{}
	keep := func(name string, open func() (io.Reader, error)) error {
		base := path.Base(name)
		if !want(base) {
			return nil
		}
		f, err := open()
		if err != nil {
			return err
		}
		files[base], err = io.ReadAll(f)
		return err
	}
	if strings.HasSuffix(url, ".zip") {
		z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range z.File {
			if err := keep(f.Name, func() (io.Reader, error) { return f.Open() }); err != nil {
				return nil, err
			}
		}
		return files, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	t := tar.NewReader(gz)
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg {
			if err := keep(h.Name, func() (io.Reader, error) { return t, nil }); err != nil {
				return nil, err
			}
		}
	}
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

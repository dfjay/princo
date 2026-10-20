package deploy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const ReleaseURL = "https://github.com/dfjay/princo/releases/download"

// princo's release workflow signs releases through Sigstore.
const (
	signerIdentity = `^https://github\.com/dfjay/princo/\.github/workflows/release\.yml@`
	signerIssuer   = "https://token.actions.githubusercontent.com"
)

// ReleaseDeb downloads princo version's .deb for a Debian architecture
// and checks it against checksums.txt, once cosign has verified that.
func ReleaseDeb(ctx context.Context, client *http.Client, baseURL, version, arch string) ([]byte, error) {
	if _, err := exec.LookPath("cosign"); err != nil {
		return nil, errors.New("cosign is needed to verify princo's release before it goes on the host; install it, or pass --princo-deb")
	}
	release := baseURL + "/v" + version + "/"
	dir, err := os.MkdirTemp("", "princo-release-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	var sums []byte
	for _, name := range []string{"checksums.txt", "checksums.txt.sigstore.json"} {
		data, err := fetch(ctx, client, release+name)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return nil, err
		}
		if name == "checksums.txt" {
			sums = data
		}
	}
	out, err := exec.CommandContext(ctx, "cosign", "verify-blob",
		"--bundle", filepath.Join(dir, "checksums.txt.sigstore.json"),
		"--certificate-identity-regexp", signerIdentity,
		"--certificate-oidc-issuer", signerIssuer,
		filepath.Join(dir, "checksums.txt"),
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("princo %s's checksums.txt fails verification: %w\n%s", version, err, bytes.TrimSpace(out))
	}

	name := fmt.Sprintf("princo_%s_%s.deb", version, arch)
	want, ok := checksum(sums, name)
	if !ok {
		return nil, fmt.Errorf("princo %s has no %s", version, name)
	}
	deb, err := fetch(ctx, client, release+name)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(deb); hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("%s doesn't match princo %s's checksums.txt", name, version)
	}
	return deb, nil
}

// checksum is name's in a sha256sum listing.
func checksum(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		sum, file, ok := strings.Cut(sc.Text(), "  ")
		if ok && file == name {
			return sum, true
		}
	}
	return "", false
}

// Command engines handles the engine releases princo deploy pins:
//
//	engines install <arch> <dir>       put them in dir, to check configs on
//	engines digests <engine> <version> print the SHA-256s to pin
package main

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/dfjay/princo/internal/deploy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "engines:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Minute}
	switch {
	case len(args) == 3 && args[0] == "install":
		return deploy.InstallReleases(ctx, client, args[1], args[2])
	case len(args) == 3 && args[0] == "digests":
		sums, err := deploy.ReleaseDigests(ctx, client, args[1], args[2])
		if err != nil {
			return err
		}
		for _, arch := range slices.Sorted(maps.Keys(sums)) {
			fmt.Printf("%q: %q,\n", arch, sums[arch])
		}
		return nil
	default:
		return fmt.Errorf("usage: engines install <arch> <dir> | engines digests <engine> <version>")
	}
}

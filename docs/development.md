# Development guide

[← README](../README.md) · [Configuration reference](config.md)

## Local setup

Clone the repository and enter the development shell:

```bash
git clone https://github.com/dfjay/princo.git
cd princo
nix develop
```

The shell provides Go, golangci-lint, sing-box, xray, age, sops, GoReleaser,
just and the Nix maintenance tools. If you use direnv, the committed `.envrc`
loads the same environment after `direnv allow`.

Without Nix, use the Go toolchain specified in [go.mod](../go.mod). Build and
run the unit tests with:

```bash
go build ./cmd/princo
go test ./...
```

## Checks

| Command | Purpose |
| --- | --- |
| `just test` | Run `go test ./...` |
| `just lint` | Check gofmt, go vet and golangci-lint |
| `just check` | Run lint, unit tests and `nix flake check`, including the NixOS VM test |
| `just golden` | Update golden engine configs and deploy bundles after intentional changes |
| `just vendor-hash` | Update `nix/package.nix` after dependency changes |
| `just snapshot` | Build a local release snapshot in `dist/` |

With `sing-box` and `xray` in `PATH`, engine tests also run `sing-box check`
and `xray run -test` on rendered configs. The NixOS VM test boots a node
from the fixture fleet. On macOS, the VM checks need a Linux builder.

CI also runs an SSH deployment end-to-end test. To run it manually, use
`just e2e user@host` with a **throwaway Debian or Ubuntu host** that already
has princo installed. The test installs software and changes host services.

## Project structure

| Path | Responsibility |
| --- | --- |
| `cmd/princo/` | CLI entrypoint |
| `internal/cli/` | Cobra commands |
| `internal/config/` | Strict YAML decoding of `princo.yaml` |
| `internal/fleet/` | Resolved model, defaults, secrets and validation |
| `internal/engine/` | Engine interface and sing-box / xray renderers |
| `internal/host/` | Node runtime files and host requirements plan |
| `internal/deploy/` | SSH deployment, engine versions and provisioning templates |
| `internal/bundle/` | Applying managed files, service checks and rollback |
| `internal/subscription/` | Share links and the subscription site |
| `internal/secrets/` | age, sops and directory-backed secrets |
| `nix/` | Package, NixOS module and VM tests |
| `testdata/` | Fixture fleet, golden configs and deploy bundles |
| `examples/` | User-facing fleet examples |

## Dependencies and engine updates

After changing `go.mod`, run `just vendor-hash` to update the Nix package's
`vendorHash`. CI does this for Dependabot PRs.

`princo deploy` installs engine releases pinned in
[`internal/deploy/engines.go`](../internal/deploy/engines.go). To update one,
generate its archive checksums, for example:

```bash
just engine-digests sing-box 1.14.4
```

Update the version and checksums in that file, then run `just golden` and
review the resulting bundle changes. The
[engines workflow](../.github/workflows/engines.yml) checks rendered configs
against both the pinned releases and nixos-unstable packages.

## Releases

[release-please](https://github.com/googleapis/release-please) maintains a release
PR from conventional commits on `main`, updating `internal/version/VERSION`
and `CHANGELOG.md`. Merging it creates the `vX.Y.Z` tag and GitHub release.
GoReleaser attaches archives, `.deb` and `.rpm` packages, completions,
checksums, the signature bundle and SBOMs.

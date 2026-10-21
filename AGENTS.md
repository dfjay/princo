# Working on princo

princo is a Go CLI that turns one `princo.yaml` into VPN server configs,
sing-box client profiles and subscriptions. It deploys nodes over SSH to
Debian/Ubuntu or through a NixOS module.

Read [README.md](README.md) for the user workflow and
[docs/development.md](docs/development.md) for setup and maintenance.

## Setup and checks

Use `nix develop` for the complete toolchain, or the Go version specified
in [go.mod](go.mod). Run `just` to list available recipes.

| Command | Purpose |
| --- | --- |
| `go build ./cmd/princo` | Build the CLI |
| `go test ./internal/<package>/...` | Test the affected package and subpackages |
| `just test` | Run all Go unit tests |
| `just lint` | Check gofmt, go vet and golangci-lint |
| `just check` | Run lint, unit tests and Nix checks, including the NixOS VM test |
| `just golden` | Update golden engine configs and deploy bundles |
| `just vendor-hash` | Update the Nix dependency hash after Go dependency changes |

Choose checks appropriate to the change. For Go changes, format changed files
with `gofmt` and run the affected tests; run `just test` and `just lint` before
finishing. For Nix module or package changes, also run `nix flake check -L`.
Report checks that could not run and why. Documentation-only changes need
link and example checks rather than a full build.

Engine tests also validate rendered configs when `sing-box` and `xray` are
available in `PATH`. On macOS, NixOS VM checks need a Linux builder.

`just e2e user@host` changes packages and services on a real host. Run it only
against a throwaway Debian/Ubuntu machine designated for testing, with princo
already installed. Never use a production node as an end-to-end test target.

## Code boundaries

- `internal/cli/`: Cobra commands, flags and input/output.
- `internal/config/`: the literal YAML schema and strict decoding.
- `internal/fleet/`: defaults, secret resolution, references and validation.
- `internal/engine/`: the engine interface and sing-box/xray renderers.
- `internal/host/`: runtime files and the host requirements plan.
- `internal/deploy/`: SSH deployment, pinned engines and provisioning templates.
- `internal/bundle/`: managed files, service checks and rollback.
- `internal/secrets/`: age, sops and directory-backed secret access.
- `internal/subscription/`: protocol links, subscription files and QR pages.
- `nix/`: packaging, NixOS integration and VM tests.

Keep YAML decoding, fleet validation and engine rendering in their respective
layers. Renderers consume the resolved fleet model; keep host provisioning
and SSH operations in the deployment layer.

## Changing behavior

- Keep generated configs and bundles deterministic. Preserve ordering where
  it controls routing, group membership or subscription presentation.
- Keep `princo plan` usable without decrypting secrets. It describes host
  requirements and secret locations, never secret values.
- Check engine capabilities and minimum versions when adding renderer features.
  Client profiles always use sing-box, regardless of the server engine.
- When changing runtime paths or host requirements, check both SSH deployment
  and the NixOS module. Preserve bundle validation and rollback behavior.
- Add regression coverage for behavior changes. Use synthetic credentials and
  existing fixture helpers; inspect golden diffs before accepting them with
  `just golden`.
- After changing Go dependencies, run `just vendor-hash` and include the
  resulting `nix/package.nix` update.

Never commit real credentials, decrypted secret files or rendered production
configs. Subscription URLs also grant access; keep them out of logs and examples.

## Documentation and commits

Keep README focused on the project overview and first successful run. Put
schema details in [docs/config.md](docs/config.md), deployment instructions in
[docs/deployment.md](docs/deployment.md), and contributor details in
[docs/development.md](docs/development.md). Keep examples consistent with the
CLI and schema. Project documentation is in English.

Use conventional commit subjects such as `fix: ...`, `feat: ...` or `docs: ...`;
release-please uses them to prepare releases. Leave release version and
changelog updates to that workflow unless the task concerns a release.

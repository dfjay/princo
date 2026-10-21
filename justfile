default:
    @just --list

# Everything CI runs
check: lint test
    nix flake check -L

# gofmt, vet, golangci-lint
lint:
    test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
    go vet ./...
    golangci-lint run

test:
    go test ./...

# Deploy the fixture fleet to a throwaway host that has this princo
e2e host:
    go build -o "${TMPDIR:-/tmp}/princo-e2e" ./cmd/princo
    PRINCO_E2E_BIN="${TMPDIR:-/tmp}/princo-e2e" PRINCO_E2E_HOST={{host}} go test -tags e2e ./e2e -count=1 -v

# Accept changed golden configs
golden:
    go test ./internal/engine/singbox ./internal/engine/xray -update

# Update vendorHash in nix/package.nix after go.mod changes
vendor-hash:
    nix-update --flake --version=skip princo

# Release dry run into dist/
snapshot:
    goreleaser release --snapshot --clean --skip=publish,sign

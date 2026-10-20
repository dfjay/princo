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

# Accept changed golden configs
golden:
    go test ./internal/engine/singbox -update

# Update vendorHash in nix/package.nix after go.mod changes
vendor-hash:
    nix-update --flake --version=skip princo

# Release dry run into dist/
snapshot:
    goreleaser release --snapshot --clean --skip=publish,sign

default:
    @just --list

# Everything CI runs
check: lint test
    nix flake check -L

# gofmt, vet, golangci-lint
lint:
    test -z "$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
    go vet ./...
    golangci-lint run

test:
    go test ./...

# Accept changed golden configs
golden:
    go test ./internal/engine/singbox -update

# Release dry run into dist/
snapshot:
    goreleaser release --snapshot --clean --skip=publish,sign

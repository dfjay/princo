# princo

Declarative CLI for sing-box (and, later, xray) VPN fleets. Alpha.

One `princo.yaml` describes the whole VPN: nodes and the protocols they
serve, users and which nodes they may use, chains of nodes, server and
client routing, and subscriptions. princo renders it into sing-box configs
(xray later) and deploys them over SSH to Ubuntu/Debian or NixOS hosts.

## What works today

- `princo.yaml` schema v1 (see `testdata/fleet/princo.yaml`):
  - nodes with VLESS-Reality, Hysteria2 and Naive sharing port 443;
  - egress through WARP, direct, or another node (chains);
  - routing rules as `match: [geosite:…, geoip:…, port:…]` plus an action;
  - client groups (selectors) picked by node tags, with fallbacks;
  - `defaults:` inherited by every node.
- Secrets in an age-encrypted `secrets.age`, at conventional paths
  (`users/<name>`, `nodes/<node>/reality`, …) or `!secret path`.
- `princo render --node N` — the node's sing-box config.
- `princo render --user U [--uris]` — the user's sing-box profile or share links.
- `princo secret get/set/list`.

Not yet: `princo deploy`, the SNI multiplexer and ACME on hosts, the
subscription site, the NixOS host module, xray.

## Quick start

```bash
go build -o princo ./cmd/princo
mkdir my-vpn && cd my-vpn

# an age identity for yourself
age-keygen -o key.txt
grep "^# public key:" key.txt | awk '{print $4}' > recipients
mkdir -p ~/.config/princo && cp key.txt ~/.config/princo/key.txt

$EDITOR princo.yaml   # start from testdata/fleet/princo.yaml

# secrets at their conventional paths
echo "$(uuidgen)" | princo secret set users/alice
sing-box generate reality-keypair   # public key → princo.yaml, private ↓
echo "<private key>" | princo secret set nodes/de/reality

princo render --node de
princo render --user alice --uris
```

## Repository layout

```
cmd/princo/        # CLI entrypoint
internal/cli/      # cobra commands
internal/config/   # princo.yaml as written (strict YAML decoding)
internal/fleet/    # resolved model: defaults, secrets, validation
internal/engine/   # Engine interface + sing-box renderer
internal/subscription/ # share links
internal/secrets/  # age-encrypted secrets store
testdata/fleet/    # fixture fleet and golden configs
```

## Development

```bash
go test ./...
go test ./internal/engine/singbox -update   # accept new golden files
```

With `sing-box` in `PATH`, the tests also run `sing-box check` on every
rendered config.

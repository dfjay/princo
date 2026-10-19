# princo

Declarative CLI for sing-box (and, later, xray) VPN fleets. Alpha.

One `princo.yaml` describes the whole VPN: nodes and the protocols they
serve, users and which nodes they may use, chains of nodes, server and
client routing, and subscriptions. princo renders it into sing-box configs
(xray later). NixOS hosts run their node through princo's NixOS module and
whatever deploy tool you use; `princo deploy` over SSH for Ubuntu/Debian is
planned.

## What works today

- `princo.yaml` schema v1 (see `testdata/fleet/princo.yaml`):
  - nodes with VLESS-Reality, Hysteria2 and Naive sharing port 443;
  - egress through WARP, direct, or another node (chains);
  - routing rules as `match: [geosite:…, geoip:…, port:…]` plus an action;
  - client groups (selectors) picked by node tags, with fallbacks;
  - `defaults:` inherited by every node.
- Secrets at conventional paths (`users/<name>`, `nodes/<node>/reality`,
  …) or `!secret path`, kept in an age-encrypted `secrets.age` or in sops
  files you already have (see below).
- `princo render --node N` — the node's sing-box config.
- `princo render --user U [--uris | --links]` — the user's sing-box profile,
  share links, or subscription links (QR page, universal, sing-box import).
- `princo render --node N --out DIR` — every file the node runs from: its
  config and, on the subscription node, the subscription site.
- `princo plan --node N` — what a deploy sets up around those files (ports,
  SNI multiplexer, certificates, rule sets, secrets), without decrypting
  anything.
- `princo secret get/set/list`.
- A NixOS module (below).

Not yet: `princo deploy`, xray.

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
princo render --user alice --links
```

## Secrets

princo asks for secrets by logical path: `users/<name>` (the user's UUID),
`shared/hy2_obfs`, `nodes/<node>/reality`, `nodes/<node>/warp/{private_key,ipv4,ipv6}`,
`nodes/<node>/chain`. By default they live in `secrets.age` next to
`princo.yaml`. A `secrets:` block sends them elsewhere — for example to
existing sops files, decrypted with the `sops` CLI and whatever keys it
knows (age, PGP on a YubiKey, cloud KMS):

```yaml
secrets:
  users/*: sops:../secrets/shared.yaml#vless_uuid_*   # users/alice → vless_uuid_alice
  shared/hy2_obfs: sops:../secrets/shared.yaml#hy2_obfs_password
  nodes/fr/*: sops:../secrets/fr.yaml                 # nodes/fr/reality → reality
```

The first matching pattern wins; `*` may only end a pattern, and in the
target key it stands for what the pattern's `*` matched. A single field can
also point anywhere with `!secret sops:file.yaml#key`. `princo secret get
<path>` shows what a path resolves to.

On a host, `--secrets-dir DIR` reads secrets from files instead, one per
path (`DIR/users/alice`), the way sops-nix or agenix lay them out. Only the
secrets the node's files need have to be there; `princo plan` lists them.

## NixOS

```nix
# flake.nix
inputs.princo.url = "github:dfjay/princo";

# the host's configuration
imports = [ inputs.princo.nixosModules.default ];
services.princo = {
  enable = true;
  config = ./vpn/princo.yaml;   # a Nix path: secret files are relative to it
  node = "fr";
};
```

Deploy it like any other NixOS configuration: `nixos-rebuild --target-host`,
colmena, deploy-rs, … At build time the module runs `princo plan` and sets
up the firewall, an nginx stream map on 443 for the multiplexer, ACME
certificates and the subscription site. Secrets come from sops-nix, using
the sops files of princo.yaml's `secrets:` block, or from
`services.princo.secretsDir`. On the host, `princo-render.service` renders
the node's files into `/run/princo/files` and sing-box runs from there, so
no secret reaches the Nix store.

The plan is read while the system is evaluated (import from derivation),
by default with a princo built for the host's platform. To evaluate
without a builder for it, plan on the machine you deploy from:

```nix
services.princo.planPkgs = inputs.nixpkgs.legacyPackages.aarch64-darwin;
```

Other HTTPS sites on the host must not listen on 443 themselves: route them
through the multiplexer with `passthrough:` and listen on its target, e.g.
`127.0.0.1:8443`.

## Repository layout

```
cmd/princo/        # CLI entrypoint
internal/cli/      # cobra commands
internal/config/   # princo.yaml as written (strict YAML decoding)
internal/fleet/    # resolved model: defaults, secrets, validation
internal/engine/   # Engine interface + sing-box renderer
internal/host/     # a node's files and the plan around them
internal/subscription/ # share links and the subscription site
internal/secrets/  # age and sops secrets, secrets dirs
nix/               # package, NixOS module (engines.nix: per-engine bits), VM test
testdata/fleet/    # fixture fleet and golden configs
```

## Development

```bash
go test ./...
go test ./internal/engine/singbox -update   # accept new golden files
```

With `sing-box` in `PATH`, the tests also run `sing-box check` on every
rendered config. `nix flake check` builds the package and boots a NixOS VM
running a node of the fixture fleet.

## License

MIT, see [LICENSE](LICENSE).

# princo

Declarative CLI for sing-box and xray VPN fleets.

One `princo.yaml` describes the whole VPN: nodes and the protocols they
serve, users and which nodes they may use, chains of nodes, server and
client routing, and subscriptions. princo renders it into sing-box or
xray configs, node by node. Debian and Ubuntu hosts get their node with `princo deploy`
over SSH; NixOS hosts run it through princo's NixOS module and whatever
deploy tool you use.

## Status

Alpha: schema v1 may still change. Works today:

- nodes with VLESS-Reality, Hysteria2 and Naive sharing port 443, egress
  direct, through WARP or through another node (chains);
- nodes running xray, with VLESS over XHTTP behind VLESS-Reality on the
  same port and keys;
- server and client routing rules, client groups selected by node tags,
  DNS on both sides;
- a subscription site: share links for most apps, the profile for
  sing-box apps, a QR page;
- secrets in an age file or in sops files you already have;
- running nodes on Debian and Ubuntu with `princo deploy`, and on NixOS
  with the NixOS module and any deploy tool.

## Install

```bash
go install github.com/dfjay/princo/cmd/princo@latest
nix run github:dfjay/princo -- --help
```

or a binary, `.deb` or `.rpm` from
[Releases](https://github.com/dfjay/princo/releases), with shell
completions and an SPDX SBOM.

## Quick start

```bash
mkdir my-vpn && cd my-vpn
curl -fsSLO https://raw.githubusercontent.com/dfjay/princo/main/examples/minimal/princo.yaml

# an age identity for yourself; secrets.age is encrypted to it
mkdir -p ~/.config/princo && age-keygen -o ~/.config/princo/key.txt
age-keygen -y ~/.config/princo/key.txt > recipients

# the node's Reality key pair: the private key is a secret...
sing-box generate reality-keypair       # prints PrivateKey and PublicKey
princo secret set nodes/nl/reality      # paste the PrivateKey (not echoed), then Enter
# ...the public one goes into princo.yaml, with your domains and ACME email
$EDITOR princo.yaml

openssl rand -hex 16 | princo secret set shared/hy2_obfs
for u in alice bob; do uuidgen | princo secret set users/$u; done

princo render --node nl               # the node's sing-box config
princo render --user alice            # alice's sing-box profile
princo render --user alice --links    # her subscription links
```

[docs/config.md](docs/config.md) describes every field of `princo.yaml`.
The node's host needs DNS records for its `address`, `naive.domain` and the
subscription domain, and nothing else listening on port 443.

## Commands

- `princo render --node N` — the node's engine config.
- `princo render --user U [--uris | --links]` — the user's sing-box
  profile, share links, or subscription links.
- `princo render --node N --out DIR` — every file the node runs from: its
  config and, on the subscription node, the subscription site.
- `princo plan --node N` — what a deploy sets up around those files (ports,
  SNI multiplexer, certificates, rule sets, secrets), without decrypting
  anything.
- `princo secret get/set/list`.
- `princo deploy --node N [--dry-run]` — run the node on its Debian or
  Ubuntu host over SSH (see below); `--dry-run` shows what would change in
  the host's files.
- `princo host apply [--check]` — on a host, as root: apply a bundle from
  stdin (files and the systemd units they restart), undoing it if a check
  or a restart fails. `princo deploy` runs it over SSH.

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

## Debian and Ubuntu

```bash
princo deploy --node fr              # to the ssh: of node fr, or --host user@host
princo deploy --node fr --dry-run    # what would change in the host's files
```

princo deploy goes over the system ssh, so your `~/.ssh/config`, agent
and known_hosts apply, as root or as a user with passwordless sudo. It

- installs the engine at the release this princo renders for, from
  SagerNet's or XTLS's GitHub release into
  `/usr/local/lib/princo/<engine>-<version>` (neither signs releases, so
  princo pins their checksums), and nginx with its stream module and
  certbot when the node needs them; opens the node's ports if ufw is
  active;
- installs princo of its own version from the release, once cosign has
  verified the release's signature (or the `.deb` of `--princo-deb`);
- issues the certificates the host lacks with certbot over HTTP-01;
  certbot's timer renews them;
- writes the node's files, `princo.service` and nginx's configs, and
  restarts what they changed. If `nginx -t`, `sing-box check` or a restart
  fails, or a restarted service stops within seconds, the old files go
  back and the services restart on them, and on the engine release they
  ran with. One deploy runs on a host at a time. xray can't reload, so
  changing its node restarts it.

The host needs DNS records for the node's domains and ports 80 and 443
open in any firewall in front of it. Rule sets are downloaded from
SagerNet for sing-box, and from Loyalsoldier/v2ray-rules-dat for xray,
cut down to the codes the node uses, unless `--rule-sets DIR` holds them. As on NixOS, other HTTPS
sites go behind the multiplexer with `passthrough:`.

## NixOS

```nix
# flake.nix
inputs.princo.url = "github:dfjay/princo";

# the host's configuration
imports = [
  inputs.sops-nix.nixosModules.sops   # or set services.princo.secretsDir
  inputs.princo.nixosModules.default
];
services.princo = {
  enable = true;
  config = ./vpn/princo.yaml;   # a Nix path: secret files are relative to it
  node = "fr";
};
```

Deploy it like any other NixOS configuration: `nixos-rebuild --target-host`,
colmena, deploy-rs, … At build time the module runs `princo plan` and sets
up the firewall, an nginx stream map on 443 for the multiplexer, ACME
certificates (HTTP-01, so port 80 is opened too) and the subscription site.
Secrets come from sops-nix, using the sops files of princo.yaml's
`secrets:` block (so every secret the node needs must be in one), or from
files under `services.princo.secretsDir`. On the host,
`princo-render.service` renders the node's files into `/run/princo/files`
and `princo.service` runs the engine on them, so no secret reaches the Nix
store. The engine comes from the host's nixpkgs
(`services.princo.enginePackage`); the module refuses one older than the
node's config needs.

The plan is read while the system is evaluated (import from derivation),
by default with a princo built for the host's platform. To evaluate
without a builder for it, plan on the machine you deploy from:

```nix
services.princo.planPkgs = inputs.nixpkgs.legacyPackages.aarch64-darwin;
```

Other HTTPS sites on the host must not listen on 443 themselves, and the
module refuses nginx virtual hosts that do: route them through the
multiplexer with `passthrough:` and listen on its target, e.g.
`127.0.0.1:8443`.

## Repository layout

```
cmd/princo/        # CLI entrypoint
internal/cli/      # cobra commands
internal/config/   # princo.yaml as written (strict YAML decoding)
internal/fleet/    # resolved model: defaults, secrets, validation
internal/engine/   # Engine interface + sing-box and xray renderers
internal/host/     # a node's files and the plan around them
internal/subscription/ # share links and the subscription site
internal/secrets/  # age and sops secrets, secrets dirs
nix/               # package, NixOS module (engines.nix: per-engine bits), VM test
testdata/fleet/    # fixture fleet and golden configs
examples/          # fleets to start from
docs/              # princo.yaml reference
```

## Development

`nix develop`, or direnv with the committed `.envrc`, gives a shell with
Go, golangci-lint, sing-box, xray, GoReleaser and just. Then:

```bash
just test          # go test ./...
just check         # everything CI runs, the NixOS VM test included
just golden        # accept changed golden configs
just vendor-hash   # update nix/package.nix after go.mod changes
```

After changing `go.mod`, run `just vendor-hash` to update the Nix
package's `vendorHash`; on Dependabot's PRs CI does it. With `sing-box` and
`xray` in `PATH`, the tests also run `sing-box check` and `xray run -test`
on every rendered config. The NixOS VM test boots a node of the fixture fleet.

`princo deploy` installs the engine releases pinned in
`internal/deploy/engines.go`. To move to a new one, put its version and
the checksums `just engine-digests sing-box 1.14.4` prints there, then
accept the changed bundles with `just golden`. The
engines workflow checks the rendered configs on those releases and on
nixos-unstable's.

Releases come from [release-please](https://github.com/googleapis/release-please):
it keeps a release PR open that bumps `internal/version/VERSION` and
`CHANGELOG.md` from the conventional commits on `main`. Merging it tags
`vX.Y.Z` and creates the release, and GoReleaser attaches the archives,
`.deb` and `.rpm` packages and the SBOM.

## License

MIT, see [LICENSE](LICENSE).

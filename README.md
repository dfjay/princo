# princo

**Your VPN fleet, in one YAML file.**

[![CI](https://github.com/dfjay/princo/actions/workflows/ci.yml/badge.svg)](https://github.com/dfjay/princo/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dfjay/princo)](https://github.com/dfjay/princo/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

princo is a declarative CLI for managing VPN servers powered by sing-box and
xray. Describe your servers, users and routing once; generate server configs,
client profiles and subscription links from the same source.

Deploy to Debian or Ubuntu over SSH, or run each node through the NixOS module.
Keep credentials in encrypted age or sops files, separate from your fleet config.

[Quick start](#quick-start) · [Configuration](docs/config.md) ·
[Deployment](docs/deployment.md) · [Contributing](docs/development.md)

> **Alpha:** princo is under active development. The `v1` configuration schema
> may still change. See the [changelog](CHANGELOG.md) for release history.

- **Manage a fleet together.** Define shared defaults, per-user access and node
  groups in one `princo.yaml`.
- **Offer several protocols on port 443.** Use VLESS-Reality, Hysteria2 and
  Naive on sing-box, or VLESS-Reality and XHTTP on xray.
- **Choose where traffic exits.** Route directly, through Cloudflare WARP or
  through another node. Set routing and DNS for both servers and clients.
- **Give each user one subscription.** Publish share links, a sing-box profile
  and a page with QR codes.
- **Inspect before deploying.** Render configs locally and inspect a node's
  host requirements without decrypting secrets.

```text
princo.yaml + encrypted secrets
                 │
                 ├── Server configs → SSH deploy / NixOS module
                 └── Client profiles + share links + subscription site
```

## Install

Download a binary or a `.deb` / `.rpm` package from
[Releases](https://github.com/dfjay/princo/releases). Release archives support
Linux (amd64, arm64) and macOS (Apple Silicon), and include shell completions.
Releases also provide checksums, a Sigstore signature bundle and SPDX SBOMs.

Or install with Go (see [go.mod](go.mod) for the required version):

```bash
go install github.com/dfjay/princo/cmd/princo@latest
princo --help
```

With Nix, run the CLI directly:

```bash
nix run github:dfjay/princo -- --help
```

## Quick start

This example creates one sing-box node, two users and a subscription site.
Both users can connect over VLESS-Reality or Hysteria2.

You need `princo` locally. To deploy, prepare a Debian or Ubuntu server with
SSH access as root or a user with passwordless sudo. Point `nl.example.com` and
`subs.example.com` at its public IP, replacing these example domains with your
own. Allow TCP 80 and 443, and UDP 443; port 443 must be available for princo.

### 1. Create your fleet

```bash
mkdir my-vpn && cd my-vpn
princo init
```

`princo init` writes a `princo.yaml` like the
[example](examples/minimal/princo.yaml) and generates its credentials: the
node's Reality key pair and a UUID for each user. They
go into `secrets.age`, encrypted to the age public key in `recipients`. Unless
it already exists, init also creates the private key at
`~/.config/princo/key.txt`; keep it outside your fleet repository and back it up.

The generated config has this structure:

```yaml
princo: v1

defaults:
  acme_email: you@example.com

nodes:
  nl:
    address: nl.example.com
    reality:
      server_name: www.microsoft.com
      short_id: 2fb419ae          # random
      public_key: UWXdEC6a...     # the generated key pair's public half
    hysteria2: {}

users:
  alice: {}
  bob: {}

client:
  groups:
    proxy: { nodes: all }
  rules:
    - { match: [ip:private], action: direct }
  final: proxy

subscription:
  node: nl
  domain: subs.example.com
```

Set your domains and ACME email in `princo.yaml`. The `reality.server_name`
is an existing HTTPS site reachable from your server; it does not need to be
a domain you own.

To add a node later, describe it in `princo.yaml` and run `princo secret gen`
to create its credentials. See the [secrets reference](docs/config.md#secrets)
to keep credentials in existing sops files instead.

### 2. Inspect and deploy

```bash
princo plan --node nl                 # Ports, certificates and required secrets
princo render --node nl               # Generated sing-box server config
princo render --user alice            # Alice's sing-box client profile
princo deploy --node nl --host root@nl.example.com
```

The deploy command installs the required software, obtains TLS certificates
and starts the node. It uses your system SSH configuration. For NixOS, follow
the [module setup](docs/deployment.md#nixos) instead.

### 3. Connect a client

```bash
princo render --user alice --links
```

Import the **Universal** link into a compatible client, use the **sing-box**
import link, or open the **QR page** on another device. Protocol support
depends on the client; XHTTP is available through share links, while generated
client profiles use sing-box and need sing-box 1.14 or newer.

After changing the fleet config or credentials, deploy again to publish the
updated server configs and subscriptions.

## Everyday commands

| Task | Command |
| --- | --- |
| Inspect host requirements without decrypting secrets | `princo plan --node nl` |
| Print a server config | `princo render --node nl` |
| Write all runtime files, including the subscription site | `princo render --node nl --out ./out` |
| Print a sing-box client profile | `princo render --user alice` |
| Print individual protocol share links | `princo render --user alice --uris` |
| Print subscription and QR links | `princo render --user alice --links` |
| Deploy using the node's `ssh:` setting | `princo deploy --node nl` |
| Preview file changes on a host with princo installed | `princo deploy --node nl --dry-run` |
| Add a user on some nodes and generate their UUID | `princo user add carol --nodes nl` |
| Replace a user's UUID, revoking their old links | `princo user rotate carol` |
| Remove a user and their UUID | `princo user remove carol` |
| Generate missing credentials after editing the config | `princo secret gen` |
| List paths in the local age store | `princo secret list` |

Use `--config PATH` (`-c`) to select another fleet config, `--key PATH` (`-k`)
for another age identity, and `princo <command> --help` for command options.
`render --out` replaces its destination directory. Rendered configs and
subscription links contain credentials; share them only with their intended users.

## Contributing

Bug reports, documentation improvements and pull requests are welcome.
For a bug, include your princo version, the command you ran and a minimal
config with credentials removed in a
[GitHub issue](https://github.com/dfjay/princo/issues).

To work on the code, start with the [development guide](docs/development.md).

Licensed under the [MIT License](LICENSE).

# Deployment guide

[← README](../README.md) · [Configuration reference](config.md)

princo runs one fleet node per host. Deploy to Debian or Ubuntu with the CLI,
or use the NixOS module with your existing NixOS deployment workflow.

## Before deploying

- Point each domain that needs a certificate at the node: the Hysteria2
  `address`, Naive's `domain` and the subscription domain, when configured.
  A Reality-only node can use an IP address.
- Allow TCP 443 and, for Hysteria2, UDP 443 in any external firewall. Allow
  TCP 80 for HTTP-01 certificate issuance and renewal when certificates are needed.
- Make port 443 available. Other HTTPS sites on the same host can use
  [`passthrough`](#sharing-port-443).
- Check `princo plan --node <name>` for the node's ports, certificates, rule
  sets and required secrets. This command does not decrypt secrets.

## Debian and Ubuntu

The target needs systemd and SSH access as root or a user with passwordless
sudo. The deploy command uses system `ssh`, so your `~/.ssh/config`, SSH agent
and `known_hosts` apply. Supported engine architectures are amd64 and arm64.

Set an SSH target on the node:

```yaml
nodes:
  nl:
    ssh: root@nl.example.com
    # ...the node's address and protocols
```

Then deploy, or override the target for this invocation:

```bash
princo deploy --node nl
princo deploy --node nl --host admin@nl.example.com
```

### What a deploy does

1. Installs nginx, its stream module and certbot when needed, and opens the
   node's ports if ufw is active.
2. Installs the engine release pinned by this version of princo, verifying
   its SHA-256 checksum. Engine files go under
   `/usr/local/lib/princo/<engine>-<version>`.
3. Installs the matching princo release after verifying its signature with
   cosign. Use `--princo-deb PATH` to supply a local `.deb` instead.
4. Obtains missing TLS certificates with certbot using HTTP-01. The certbot
   timer handles renewal.
5. Applies the rendered files, rule sets, `princo.service` and nginx config,
   restarting or reloading services whose files changed.

The rendered files live in `/var/lib/princo/files`. Rule sets are downloaded
from SagerNet for sing-box and Loyalsoldier/v2ray-rules-dat for xray. xray's
data files are reduced to the codes the node uses. To provide rule sets
locally, pass `--rule-sets DIR`.

### Previewing changes and handling failures

On a host that already has princo installed:

```bash
princo deploy --node nl --dry-run
```

This connects to the host and reports changes to the managed files without
applying them. It requires secrets locally and may download rule sets. It
does not preview package installation or certificate issuance; for a new
host, inspect `princo plan` before the first deploy.

When applying a bundle, princo checks the engine config and `nginx -t` as
needed. If a check or service restart fails, or a restarted service stops
within the health-check window, it restores the previous managed files and
restarts the affected services on them. The previous engine release remains
available during this rollback. Package installation and certificate issuance
are outside the bundle rollback. Only one deploy runs on a host at a time.
xray config changes require a restart.

`princo host apply [--check]` is the lower-level command used by deploy.
It runs as root on the host and reads a bundle from stdin; ordinary usage
does not require calling it yourself.

## NixOS

Add princo to your flake inputs:

```nix
inputs.princo.url = "github:dfjay/princo";
```

Import the module in the host configuration:

```nix
imports = [
  inputs.sops-nix.nixosModules.sops
  inputs.princo.nixosModules.default
];

services.princo = {
  enable = true;
  config = ./vpn/princo.yaml;
  node = "nl";
};
```

This example assumes you already have sops-nix as an input and have configured
its decryption keys on the host. Map **every secret the node needs** to a sops
file in `princo.yaml`'s [`secrets:` block](config.md#secrets). The module uses
those mappings to declare sops-nix secrets.

Alternatively, provide files with agenix or another secret manager, omit the
sops-nix import, and set:

```nix
services.princo.secretsDir = "/run/princo-secrets";
```

Each logical secret path is a file under this directory, for example
`/run/princo-secrets/users/alice`. `princo plan --node nl` lists the required
paths and filenames. The quick start's local `secrets.age` store is not
automatically decrypted by the NixOS module.

Pass `config` as a Nix path, as above. Secret file references are relative
to its directory, so include the referenced encrypted files in the source
available to Nix.

Deploy through your usual tool: `nixos-rebuild --target-host`, colmena or
deploy-rs. The module:

- runs `princo plan` during evaluation to configure the firewall, nginx SNI
  multiplexer, ACME certificates and subscription site;
- renders the node's files into `/run/princo/files` on the host through
  `princo-render.service`, keeping decrypted secrets out of the Nix store;
- runs the engine through `princo.service` and checks its minimum required
  version.

The engine and its rule sets come from `services.princo.enginePkgs`. With
princo's flake that is its own nixpkgs input, nixos-unstable, which follows
engine releases more closely than a stable channel. Make it follow yours with
`inputs.princo.inputs.nixpkgs.follows`, or set `enginePkgs` or
`enginePackage` directly; a stable channel may carry an engine older than
princo needs.

### Evaluating from another platform

The plan uses import from derivation. By default, evaluating a system needs
a builder for the target host's platform. To run the plan on your deployment
machine instead, select its package set:

```nix
services.princo.planPkgs = inputs.nixpkgs.legacyPackages.aarch64-darwin;
```

## Sharing port 443

When protocols or HTTPS sites share TCP 443, princo configures an nginx
stream multiplexer that routes connections by TLS server name (SNI).
Hysteria2 uses UDP and bypasses it.

An existing HTTPS site must listen on a separate local port. Add its domain
and target to the node:

```yaml
passthrough:
  example.com: 127.0.0.1:8443
```

Configure that site's HTTPS listener on `127.0.0.1:8443`; the multiplexer
forwards TLS unchanged, so the site still handles its own certificate.
The NixOS module rejects nginx virtual hosts that also try to listen on 443.

Reality and Naive behind the multiplexer see the client address as
`127.0.0.1`; the sing-box path does not forward the original address through
the PROXY protocol.

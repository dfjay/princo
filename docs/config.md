# princo.yaml reference

[← README](../README.md) · [Deployment guide](deployment.md)

`princo.yaml` describes your servers, who can use them, and how traffic is
routed. Start from the [minimal fleet](../examples/minimal/princo.yaml), or
explore the [test fixture](../testdata/fleet/princo.yaml) for WARP, chains,
custom DNS and both engines.

Unknown YAML fields are errors. After parsing, princo checks references and
settings together and reports the validation problems it finds in one pass.

[Defaults](#defaults) · [Nodes](#nodesname) · [Users](#usersname) ·
[Client profiles](#client) · [Rules](#rules) · [DNS](#dns) ·
[Engines](#engines) · [Subscriptions](#subscription) · [Secrets](#secrets)

## File structure

The top-level sections are:

```yaml
princo: v1          # schema version, required
defaults: {}        # inherited by every node
nodes: {}           # servers
users: {}           # who may connect, and where
client: {}          # the profile users' apps get
secrets: {}         # where secrets live
# subscription:    # optional site users import profiles from
#   node: nl
#   domain: subs.example.com
```

This is an outline; add your nodes and users before rendering. Omit optional
sections you do not need. By default, nodes use sing-box with direct egress,
and unmatched client traffic goes directly unless `client.final` selects a
proxy group.

Names of nodes, users and client groups appear in links, tags and file
paths, so they are lowercase letters, digits, `-` and `_`, starting and
ending with a letter or digit; keep them short, like `fr` or `alice`.

Use `princo --config PATH plan --node <name>` to validate settings and inspect
host requirements without decrypting secrets. Render with
`princo --config PATH render --node <name>` once credentials are available.

## Secret values

Fields marked *secret* can be omitted: princo then looks up their conventional
paths in the secret store. Keep credentials in the store so the fleet config
can be shared without exposing them.

| Path | Value |
| --- | --- |
| `users/<user>` | the user's UUID |
| `nodes/<node>/reality` | the node's Reality private key |
| `shared/hy2_obfs` | the Hysteria2 obfuscation password, shared by all nodes |
| `nodes/<node>/warp/{private_key,ipv4,ipv6}` | the node's WARP account |
| `nodes/<node>/chain` | the UUID a chained node uses on its upstream |

`princo secret gen` generates every missing one it can: UUIDs, Reality key
pairs (writing the public half to the node's `reality.public_key`) and the
Hysteria2 password. WARP credentials come from an existing account.

To use another path, set the field to `!secret <path>`, or point it at a
file directly with `!secret sops:<file>#<key>` or `!secret age:<file>#<key>`.
Literal strings are also accepted. The [`secrets` section](#secrets) describes
storage, mapping rules and host-side secret files.

## `defaults`

Every node inherits these; a node's own value wins.

| Field | Default | Description |
| --- | --- | --- |
| `engine` | `sing-box` | what the nodes run: `sing-box` or `xray` (see [Engines](#engines)) |
| `acme_email` | — | the email ACME certificates are registered with |
| `reality` | — | default `server_name`, `short_id` of `reality` blocks |
| `xhttp` | — | default `path`, `mode` of `xhttp` blocks |
| `hysteria2` | — | default `masquerade`, `obfs_password` of `hysteria2` blocks |
| `egress` | `direct` | see `nodes.<name>.egress` |
| `dns` | — | see [DNS](#dns); a node's block replaces the default block |
| `rules` | — | see [Rules](#rules); a node's `rules`, even empty, replace them |

A protocol block in `defaults` only supplies values: a node serves a
protocol when it has its own block, even an empty one (`hysteria2: {}`).

## `nodes.<name>`

| Field | Description |
| --- | --- |
| `address` | the host name or IP apps connect to; required for `reality` and `hysteria2` |
| `reality` | serve VLESS-Reality over TCP 443 |
| `xhttp` | serve VLESS over XHTTP behind `reality` (xray only) |
| `hysteria2` | serve Hysteria2 over UDP 443 |
| `naive` | serve NaiveProxy over TCP 443 |
| `egress` | where traffic leaves: `direct`, `warp`, or another node's name |
| `warp` | the WARP account for `egress: warp` (*secret* fields) |
| `tags` | labels client groups select nodes by |
| `ipv6` | defaults to `true`; set `false` when the node has no IPv6, so the client refuses IPv6 destinations and AAAA answers for traffic routed through it |
| `passthrough` | other TLS sites on 443: `host: target` (see below) |
| `dns`, `rules`, `engine`, `acme_email` | override `defaults` |
| `ssh` | `user@host` or a `~/.ssh/config` Host that `princo deploy` connects to |

A node needs at least one protocol. All of them share port 443: Reality,
XHTTP and Naive over TCP, Hysteria2 over UDP.

### `reality`

| Field | Description |
| --- | --- |
| `server_name` | a real HTTPS site the node imitates, e.g. `www.microsoft.com`; pick one reachable from the node |
| `short_id` | hex, up to 16 characters (`openssl rand -hex 4`) |
| `public_key` | set by `princo secret gen nodes/<node>/reality`, or from `sing-box generate reality-keypair` or `xray x25519` (its `Password`) |
| `private_key` | *secret*, `nodes/<node>/reality` |

### `xhttp`

| Field | Default | Description |
| --- | --- | --- |
| `path` | — | required HTTP path, e.g. `/f7Kq2m`; each `/`-separated segment uses letters, digits, `.`, `_`, `~`, `-` |
| `mode` | `auto` | how apps carry the upload: `auto`, `packet-up`, `stream-up` or `stream-one` |

XHTTP rides on the node's `reality`: same port, server name and keys.
Whatever reaches the Reality inbound and isn't VLESS over a raw TLS
stream falls back to the XHTTP inbound. sing-box apps can't use XHTTP,
so it is only in share links.

### `hysteria2`

| Field | Description |
| --- | --- |
| `masquerade` | the site served to probes; defaults to `https://<reality.server_name>`, required when Reality is absent and no default is set |
| `obfs_password` | *secret*, `shared/hy2_obfs` |

Hysteria2 needs a certificate for `address`, so `address` must then be a
domain pointing at the node.

### `naive`

| Field | Description |
| --- | --- |
| `domain` | the domain Naive is served on; needs a certificate and a DNS record pointing at the node |

### `egress`

- `direct`: out of the node itself.
- `warp`: through Cloudflare WARP, with the node's `warp` account.
- `<node>`: through another node over VLESS-Reality (a chain). The
  upstream needs `reality`; the hop uses the *secret* `nodes/<node>/chain`
  as its UUID there. Chains may be longer than one hop but can't loop.

For example, on a node named `relay`, `egress: fr` sends traffic through
`fr` using the credential at `nodes/relay/chain`.

### `warp`

For `egress: warp`, provide an existing WARP account. princo reads its
credentials; it does not register an account.

| Field | Conventional secret path | Description |
| --- | --- | --- |
| `private_key` | `nodes/<node>/warp/private_key` | WireGuard private key |
| `ipv4` | `nodes/<node>/warp/ipv4` | WARP interface IPv4 address |
| `ipv6` | `nodes/<node>/warp/ipv6` | WARP interface IPv6 address |

All three fields are *secret* and can be omitted when stored at their
conventional paths.

### `passthrough`

The node multiplexes 443 by TLS server name: Naive's domain and the
subscription domain go to their servers, the rest to Reality. Other HTTPS
sites on the same host join through `passthrough`:

```yaml
passthrough:
  example.com: 127.0.0.1:8443   # the site listens there, not on 443
```

The multiplexer passes connections on as they are, so Reality and Naive
see every client as `127.0.0.1`; sing-box no longer accepts the PROXY
protocol that would carry the address. Hysteria2 is UDP and bypasses it.
See [Sharing port 443](deployment.md#sharing-port-443) for host setup.

## `users.<name>`

| Field | Description |
| --- | --- |
| `nodes` | node names the user may use, in the order their app lists them; all nodes when unset |
| `uuid` | *secret*, `users/<name>` |

Manage users with `princo user add`, `rotate` and `remove`; see
[Writing secrets](#writing-secrets).

## `client`

The sing-box profile users import.

| Field | Description |
| --- | --- |
| `groups` | selectors in the app, in order (see below) |
| `dns` | the app's resolver, see [DNS](#dns) |
| `rules` | see [Rules](#rules) |
| `final` | where unmatched traffic goes: a group or `direct` (the default) |

### `client.groups.<name>`

| Field | Default | Description |
| --- | --- | --- |
| `nodes` | `all` | members: `all`, `<tag>`, or `!<tag>` (without the tag) |
| `default` | `first` | the preselected member: `first`, `direct`, or an outbound tag such as `fr-reality` |
| `include_direct` | `false` | also offer `direct` |
| `fallback` | — | a group or `direct` to use when the user has no members here |

Every node a user may use contributes one member per protocol, tagged
`<node>-reality`, `<node>-hy2`, `<node>-naive`. `direct` is reserved.
XHTTP has no member: sing-box doesn't speak it.

For example, tag a node with `tags: [europe]`, then use a group with
`nodes: europe` to offer its protocols. Quote negated selectors in YAML:
`nodes: "!europe"`.

## Rules

A rule matches traffic and decides where it goes. The first matching rule
wins, except `sniff`, which inspects traffic and continues to the next rule.
For example, on a node:

```yaml
rules:
  - { match: [port:25, port:465], action: reject }
  - { action: sniff }
  - { match: [geosite:category-ru, geoip:ru], action: direct }
```

Client rules can route through a group defined in `client.groups`:

```yaml
client:
  rules:
    - { match: [geosite:category-ru, geoip:ru], via: ru-select }
```

| Field | Description |
| --- | --- |
| `match` | conditions, any of which matches; required except for `sniff` |
| `action` | on nodes: `direct`, `reject` or `sniff` (detect the protocol and domain, then go on); in the client: `direct` or `reject` |
| `via` | client only, instead of `action`: send through a group |

Conditions are `kind:value`:

| Kind | Example |
| --- | --- |
| `geosite` | `geosite:category-ru` (sing-geosite rule sets) |
| `geoip` | `geoip:ru` (sing-geoip rule sets) |
| `domain`, `domain_suffix`, `domain_keyword` | `domain_suffix:example.com` |
| `ip` | `ip:10.0.0.0/8`, or `ip:private` for private and loopback ranges |
| `port` | `port:443` |
| `network` | `network:udp` (`tcp`, `udp`, `icmp`) |

## DNS

For a node (`defaults.dns`, `nodes.<name>.dns`) or the client
(`client.dns`).

```yaml
dns:
  servers:
    quad9: { address: https://dns.quad9.net, resolver: bootstrap }
    bootstrap: { address: 9.9.9.9 }
  final: quad9
  default_resolver: bootstrap
  strategy: prefer_ipv4
```

| Field | Description |
| --- | --- |
| `servers.<name>.address` | `udp://`, `tcp://`, `tls://`, `quic://`, `https://` URL, or a bare IP (UDP) |
| `servers.<name>.resolver` | another server that resolves this one's host name |
| `servers.<name>.via` | client only: send queries through a group |
| `final` | the server for everything else; required |
| `default_resolver` | resolves the host names of outbounds |
| `strategy` | `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` |
| `optimistic` | answer from an expired cache while refreshing |
| `rules` | `{ match: [...], server: <name> }`; domain conditions only |

## Engines

| Protocol | sing-box | xray |
| --- | --- | --- |
| `reality` | yes | yes |
| `xhttp` | no | yes |
| `hysteria2` | yes | no |
| `naive` | yes | no |

On xray nodes:

- DNS servers can't be `tls://`, and are queried directly; their host
  names are resolved by the system, as xray has no `resolver` per server.
- `network:icmp` can't be matched.
- `action: sniff` turns on sniffing for the whole inbound, so every rule
  sees the sniffed domain, wherever the `sniff` rule stands.

Users' apps get the same subscription whatever engine the nodes run.

## `subscription`

| Field | Description |
| --- | --- |
| `node` | the node that serves the site |
| `domain` | its domain; needs a DNS record pointing at that node |

Each user gets `https://<domain>/<token>/`, where the token comes from
their UUID: share links for most apps, the profile for sing-box apps, and
a QR page at `/qr`. `princo render --user <name> --links` prints them.
The sing-box profile is served at `/<token>/sing-box`. Tokens stay stable
across renders; changing a user's UUID changes their subscription URL.
Deploy the subscription node after changing users or their access so its
published profiles are updated.

## `secrets`

Maps secret paths to where they're stored: `sops:<file>` or
`age:<file>`, optionally with `#<key>`, relative to princo.yaml. The first
matching pattern wins; unmatched paths come from `secrets.age` next to
princo.yaml.

```yaml
secrets:
  users/*: sops:../secrets/shared.yaml#vless_uuid_*
  shared/hy2_obfs: sops:../secrets/shared.yaml#hy2_obfs_password
  nodes/fr/*: sops:../secrets/fr.yaml
```

`*` may only end a pattern; in the key it stands for what it matched.
Without a key, the key is what `*` matched (`nodes/fr/reality` →
`reality`), or the whole path for a pattern without `*`.

### Writing secrets

The default identity is `~/.config/princo/key.txt`; override it with `--key`.
Commands that write secrets follow the mappings: they update mapped sops
files with `sops set` (sops 3.11 or newer) and age files encrypted to the
recipients in `.princo/recipients`, falling back to `recipients`, next to
`princo.yaml`. When the recipients don't include the identity, they refuse
to write, since the identity couldn't read the file back. Unmapped paths go
to `secrets.age`, which is created when needed.

| Command | Effect |
| --- | --- |
| `princo secret gen [path...]` | generate missing secrets, or the given ones; `--force` replaces existing values |
| `princo secret set <path>` | store a value read from a hidden prompt or the first line of stdin |
| `princo secret get <path>` | print the resolved value |
| `princo secret list` | list the paths in `secrets.age` |
| `princo user add <name> [--nodes a,b]` | add a user to `princo.yaml` and generate their UUID |
| `princo user rotate <name>` | replace the user's UUID; their subscription link changes with it |
| `princo user remove <name>` | remove the user from `princo.yaml` and delete their UUID |

`princo init` starts a fleet with these: see the
[quick start](../README.md#1-create-your-fleet). princo edits `princo.yaml`
in place, keeping comments and layout, and refuses an edit that would change
more than intended. `user add` and `user remove` need `users:` written as an
indented block.

### Host-side secret files

Pass `--secrets-dir DIR` to read already decrypted files instead of the
encrypted stores. Logical paths retain their structure: `users/alice` reads
`DIR/users/alice`. Explicit `sops:` or `age:` locations use derived filenames;
`princo plan --node <name>` lists the exact names in its `secrets[].file` fields.

Only the secrets needed for the node's runtime files must be present. A node
serving subscriptions also needs credentials used to generate its users'
profiles. See the [NixOS guide](deployment.md#nixos) for sops-nix and custom
secret directories.

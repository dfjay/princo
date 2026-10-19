# princo.yaml reference

One file describes the whole fleet. princo checks it strictly: unknown
fields are errors, and every problem is reported at once.
[`examples/minimal/princo.yaml`](../examples/minimal/princo.yaml) is a
small fleet to start from;
[`testdata/fleet/princo.yaml`](../testdata/fleet/princo.yaml) uses every
feature.

```yaml
princo: v1          # schema version, required
defaults: {}        # inherited by every node
nodes: {}           # servers
users: {}           # who may connect, and where
client: {}          # the profile users' apps get
subscription: {}    # the site users import it from
secrets: {}         # where secrets live
```

Names of nodes, users and client groups appear in links, tags and file
paths; keep them short, like `fr` or `alice`.

## Secrets

A field marked *secret* below is never written in princo.yaml. Each has a
conventional path, and princo looks it up there (see
[Secrets](../README.md#secrets) for where paths are stored):

| Path | What |
|---|---|
| `users/<user>` | the user's UUID (`uuidgen`) |
| `nodes/<node>/reality` | the node's Reality private key |
| `shared/hy2_obfs` | the Hysteria2 obfuscation password, shared by all nodes |
| `nodes/<node>/warp/{private_key,ipv4,ipv6}` | the node's WARP account |
| `nodes/<node>/chain` | the UUID a chained node uses on its upstream |

To use another path, set the field to `!secret <path>`, or point it at a
file directly with `!secret sops:<file>#<key>` or `!secret age:<file>#<key>`.

## `defaults`

Every node inherits these; a node's own value wins.

| Field | Default | |
|---|---|---|
| `engine` | `sing-box` | what the nodes run (only `sing-box` for now) |
| `acme_email` | | the email ACME certificates are registered with |
| `reality` | | default `server_name`, `short_id` of `reality` blocks |
| `hysteria2` | | default `masquerade`, `obfs_password` of `hysteria2` blocks |
| `egress` | `direct` | see `nodes.<name>.egress` |
| `dns` | | see [DNS](#dns) |
| `rules` | | see [Rules](#rules); a node's `rules`, even empty, replace them |

A protocol block in `defaults` only supplies values: a node serves a
protocol when it has its own block, even an empty one (`hysteria2: {}`).

## `nodes.<name>`

| Field | |
|---|---|
| `address` | the host name or IP apps connect to; required for `reality` and `hysteria2` |
| `reality` | serve VLESS-Reality over TCP 443 |
| `hysteria2` | serve Hysteria2 over UDP 443 |
| `naive` | serve NaiveProxy over TCP 443 |
| `egress` | where traffic leaves: `direct`, `warp`, or another node's name |
| `warp` | the WARP account for `egress: warp` (*secret* fields) |
| `tags` | labels client groups select nodes by |
| `ipv6` | `false` when the node has no IPv6: the client then refuses IPv6 destinations and AAAA answers for traffic routed through it |
| `passthrough` | other TLS sites on 443: `host: target` (see below) |
| `dns`, `rules`, `engine`, `acme_email` | override `defaults` |
| `ssh` | `user@host` for `princo deploy` (planned) |

A node needs at least one protocol. All of them share port 443: Reality
and Naive over TCP, Hysteria2 over UDP.

### `reality`

| Field | |
|---|---|
| `server_name` | a real HTTPS site the node imitates, e.g. `www.microsoft.com`; pick one reachable from the node |
| `short_id` | hex, up to 16 characters (`openssl rand -hex 4`) |
| `public_key` | from `sing-box generate reality-keypair` |
| `private_key` | *secret*, `nodes/<node>/reality` |

### `hysteria2`

| Field | |
|---|---|
| `masquerade` | the site served to probes; defaults to `https://<reality.server_name>` |
| `obfs_password` | *secret*, `shared/hy2_obfs` |

Hysteria2 needs a certificate for `address`, so `address` must then be a
domain pointing at the node.

### `naive`

| Field | |
|---|---|
| `domain` | the domain Naive is served on; needs a certificate and a DNS record pointing at the node |

### `egress`

- `direct`: out of the node itself.
- `warp`: through Cloudflare WARP, with the node's `warp` account.
- `<node>`: through another node over VLESS-Reality (a chain). The
  upstream needs `reality`; the hop uses the *secret* `nodes/<node>/chain`
  as its UUID there. Chains may be longer than one hop but can't loop.

### `passthrough`

The node multiplexes 443 by TLS server name: Naive's domain and the
subscription domain go to their servers, the rest to Reality. Other HTTPS
sites on the same host join through `passthrough`:

```yaml
passthrough:
  example.com: 127.0.0.1:8443   # the site listens there, not on 443
```

## `users.<name>`

| Field | |
|---|---|
| `nodes` | node names the user may use, in the order their app lists them; all nodes when unset |
| `uuid` | *secret*, `users/<name>` |

## `client`

The sing-box profile users import.

| Field | |
|---|---|
| `groups` | selectors in the app, in order (see below) |
| `dns` | the app's resolver, see [DNS](#dns) |
| `rules` | see [Rules](#rules) |
| `final` | where unmatched traffic goes: a group or `direct` (the default) |

### `client.groups.<name>`

| Field | Default | |
|---|---|---|
| `nodes` | `all` | members: `all`, `<tag>`, or `!<tag>` (without the tag) |
| `default` | `first` | the preselected member: `first`, `direct`, or an outbound tag such as `fr-reality` |
| `include_direct` | `false` | also offer `direct` |
| `fallback` | | a group or `direct` to use when the user has no members here |

Every node a user may use contributes one member per protocol, tagged
`<node>-reality`, `<node>-hy2`, `<node>-naive`. `direct` is reserved.

## Rules

A rule matches traffic and decides where it goes. The first matching rule
wins.

```yaml
rules:
  - { match: [port:25, port:465], action: reject }
  - { action: sniff }
  - { match: [geosite:category-ru, geoip:ru], via: ru-select }
```

| Field | |
|---|---|
| `match` | conditions, any of which matches; required except for `sniff` |
| `action` | on nodes: `direct`, `reject` or `sniff` (detect the protocol and domain, then go on); in the client: `direct` or `reject` |
| `via` | client only, instead of `action`: send through a group |

Conditions are `kind:value`:

| Kind | Example |
|---|---|
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

| Field | |
|---|---|
| `servers.<name>.address` | `udp://`, `tcp://`, `tls://`, `quic://`, `https://` URL, or a bare IP (UDP) |
| `servers.<name>.resolver` | another server that resolves this one's host name |
| `servers.<name>.via` | client only: send queries through a group |
| `final` | the server for everything else; required |
| `default_resolver` | resolves the host names of outbounds |
| `strategy` | `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` |
| `optimistic` | answer from an expired cache while refreshing |
| `rules` | `{ match: [...], server: <name> }`; domain conditions only |

## `subscription`

| Field | |
|---|---|
| `node` | the node that serves the site |
| `domain` | its domain; needs a DNS record pointing at that node |

Each user gets `https://<domain>/<token>/`, where the token comes from
their UUID: share links for most apps, the profile for sing-box apps, and
a QR page at `/qr`. `princo render --user <name> --links` prints them.

## `secrets`

Maps secret paths to where they're stored: `sops:<file>` or
`age:<file>`, optionally with `#<key>`, relative to princo.yaml. The first
matching pattern wins; unmatched paths come from `secrets.age` next to
princo.yaml.

```yaml
secrets:
  users/*: sops:../secrets/shared.yaml#vless_uuid_*
  nodes/fr/*: sops:../secrets/fr.yaml
```

`*` may only end a pattern; in the key it stands for what it matched.
Without a key, the key is what `*` matched (`nodes/fr/reality` →
`reality`), or the whole path for a pattern without `*`.

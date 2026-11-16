# princo.yaml reference

[← README](../README.md) · [Deployment guide](deployment.md)

`princo.yaml` describes your servers, who can use them, and how traffic is
routed. Start from the [minimal fleet](../examples/minimal/princo.yaml), or
explore the [test fixture](../testdata/fleet/princo.yaml) for WARP, chains,
custom DNS and both engines.

Unknown YAML fields are errors. After parsing, princo checks references and
settings together and reports the validation problems it finds in one pass.

[Defaults](#defaults) · [Nodes](#nodesname) · [Users](#usersname) ·
[Client profiles](#client) · [Rules](#rules) · [Rule data](#rule_data) ·
[DNS](#dns) · [Engines](#engines) · [Subscriptions](#subscription) ·
[Monitor](#monitor) · [Secrets](#secrets) · [Several files](#several-files)

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
#   domains: [subs.example.com]
# certificates: {}  # wildcards and certificates issued elsewhere
# rule_data: runetfreedom  # where geoip: and geosite: data comes from
# monitor: {}       # nodes check themselves and report what changed
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
| `shared/hysteria2_obfs` | the Hysteria2 obfuscation password, shared by nodes with `obfs` |
| `nodes/<node>/warp/{private_key,ipv4,ipv6}` | the node's WARP account |
| `nodes/<node>/chain` | the UUID a chained node uses on its upstream |
| `nodes/<node>/api` | the secret of the engine's API, with `stats: true` or, on a node with `egress: warp`, [`monitor`](#monitor) |
| `nodes/<node>/monitor` | the UUID a node sends its reports with through the nodes of a channel's [`via`](#notify) |
| `monitor/<channel>/token`, `monitor/<channel>/chat` | the bot and the chat of a Telegram channel of [`monitor`](#monitor) |
| `monitor/<channel>/url` | the URL of a webhook channel of [`monitor`](#monitor) |

`princo secret gen` generates every missing one it can: UUIDs, Reality key
pairs (writing the public half to the node's `reality.public_key`) and the
Hysteria2 obfuscation password. WARP credentials come from an existing account,
and the monitor's channels have their own.

To use another path, set the field to `!secret <path>`: for example, two
nodes can share a Reality key with `private_key: !secret shared/reality`.
A path consists of segments containing letters, digits, `-` and `_`,
separated by `/`. Literal secret values are also accepted, but expose the
credential in the config.

Storage locations belong in the [`secrets:` block](#secrets).
`!secret sops:<file>#<key>` and `!secret age:<file>#<key>` are no longer
supported. Replace them with a logical path, then map it to the same
storage location in `secrets:`.

## `defaults`

Every node inherits these; a node's own value wins.

| Field | Default | Description |
| --- | --- | --- |
| `engine` | `sing-box` | what the nodes run: `sing-box` or `xray` (see [Engines](#engines)) |
| `acme_email` | — | the email ACME certificates are registered with |
| `reality` | — | default `server_name`, `short_id` of `reality` blocks |
| `xhttp` | — | default `path`, `mode` of `xhttp` blocks |
| `hysteria2` | — | default `masquerade`, `obfs`, `obfs_password` of `hysteria2` blocks |
| `egress` | `direct` | see `nodes.<name>.egress` |
| `dns` | — | see [DNS](#dns); a node's block replaces the default block |
| `rules` | — | see [Rules](#rules); a node's `rules`, even empty, replace them |
| `log` | `warn` | the engine's log level: `debug`, `info`, `warn`, `error` or `none` |
| `stats` | `false` | report connections to [`princo stats`](deployment.md#watching-who-connects) (sing-box only); its API's secret is at `nodes/<node>/api` |

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
| `ipv6` | defaults to `true`; set `false` when the node has no IPv6, so the client refuses IPv6 destinations and AAAA answers for traffic routed through it; for the user's own network see [`client`](#client) |
| `passthrough` | other TLS sites on 443: `host: target` (see below) |
| `dns`, `rules`, `engine`, `acme_email`, `log`, `stats` | override `defaults` |
| `ssh` | `user@host` or a `~/.ssh/config` Host that `princo deploy` connects to |

A node needs at least one protocol. All of them share port 443: Reality,
XHTTP and Naive over TCP, Hysteria2 over UDP.

### `reality`

| Field | Description |
| --- | --- |
| `server_name` | a real HTTPS site the node imitates, e.g. `www.microsoft.com`; pick one reachable from the node |
| `target` | `host:port` of the site that takes the handshakes of whoever isn't a client; `<server_name>:443` by default |
| `short_id` | hex, up to 16 characters (`openssl rand -hex 4`) |
| `public_key` | set by `princo secret gen nodes/<node>/reality`, or from `sing-box generate reality-keypair` or `xray x25519` (its `Password`) |
| `private_key` | *secret*, `nodes/<node>/reality` |

Whoever connects without being a client, a scanner included, gets
`server_name`'s site. By default that is someone else's, while the node's
own domain points at it. With self-steal, the node imitates a site of its
own instead, so its name, certificate and site agree:

```yaml
nodes:
  fr:
    address: fr.example.com
    reality:
      server_name: fr.example.com
      target: 127.0.0.1:8443   # an HTTPS site for fr.example.com on the node
```

The site is yours to serve, with a certificate for `server_name`. Reality
uses it for clients' handshakes too, so it must speak TLS 1.3 with X25519
key exchange, as nginx does by default, and should speak HTTP/2; check it
with `curl -v --resolve <server_name>:<port>:<host> https://<server_name>:<port>/`.
Hysteria2's default masquerade, `https://<server_name>`, reaches it too.
`server_name` can't be a name the multiplexer sends elsewhere: drop a
`passthrough` entry for it and set `target` to that entry's address.
Nor can `target` be Reality itself, on 443 of the node or `127.0.0.1:8444`
behind the multiplexer: the handshake would come back around. princo
catches the node's address and loopback, but doesn't resolve names, so a
`target`, or a `server_name` without one, mustn't be another name of the
node on 443; for self-steal, always set `target`.

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
| `masquerade` | without `obfs`: the site served to probes; defaults to `https://<reality.server_name>`, required when Reality is absent and no default is set |
| `obfs` | `salamander` or `gecko` to obfuscate the traffic; `none` by default, or to turn off a default. Gecko is experimental, and few apps besides recent sing-box and Hysteria clients support it |
| `obfs_password` | with `obfs`: *secret*, `shared/hysteria2_obfs` |

Without `obfs`, the node is an HTTP/3 server: apps authenticate, and
anyone else gets the `masquerade` site. Obfuscation scrambles every packet,
which helps where QUIC itself is blocked, but the node no longer looks like
an HTTP/3 server and has no site to show, so `masquerade` can't be set with it.
A node takes the defaults that fit its mode: `masquerade` without `obfs`,
`obfs_password` with it.

Hysteria2 needs a [certificate](#certificates) for `address`, so `address`
must then be a domain pointing at the node.

### `naive`

| Field | Description |
| --- | --- |
| `domain` | the domain Naive is served on; needs a [certificate](#certificates) and a DNS record pointing at the node |

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
conventional paths. Some accounts also need `reserved`, the 3 bytes of
their client ID, e.g. `reserved: [12, 34, 56]`.

`endpoint` overrides the WARP peer, `engage.cloudflareclient.com:2408` by
default. Cloudflare also answers on UDP 500, 1701 and 4500, useful where 2408
is blocked, e.g. `endpoint: engage.cloudflareclient.com:4500`. Bracket IPv6
addresses: `"[2606:4700:d0::a29f:c001]:4500"`.

### `passthrough`

The node multiplexes 443 by TLS server name: Naive's domain and the
subscription domains go to their servers, the rest to Reality. Other HTTPS
sites on the same host join through `passthrough`:

```yaml
passthrough:
  example.com: 127.0.0.1:8443   # the site listens there, not on 443
  static.example.net: 203.0.113.7:443   # or another host, by its IP
```

The multiplexer passes connections on as they are, and Reality and Naive
still see each client's address: nginx connects to them from it. Targets
see nginx's own address; give another host by IP, as nginx resolves no
names there. Hysteria2 is UDP and bypasses it.
See [Sharing port 443](deployment.md#sharing-port-443) for host setup.

## `users.<name>`

| Field | Description |
| --- | --- |
| `nodes` | node names the user may use, in the order their app lists them; all nodes when unset |
| `uuid` | *secret*, `users/<name>` |
| `client` | the user's own profile settings, merged over [`client`](#client) |

A user's `client:` takes the fields of `client:` and merges over it as
[several files](#merge-rules) do: mappings key by key, lists replaced
whole. For example, a router, with nobody to pick a node, uses whichever
works:

```yaml
client:
  groups:
    select: { nodes: all }
  final: select

users:
  router:
    nodes: [fr, us]
    client:            # select picks a working node; final stays select
      groups:
        select: { auto: true, default: auto }
```

The subscription site serves each user their own profile. What a device
runs on is no user's setting, as one user has several: see
[platforms](#platforms).

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
| `log` | the app's log level, as for nodes; `warn` by default |
| `ipv6` | whether the user's own network has IPv6, for traffic that leaves directly; unset, the app checks (see below) |

Traffic that leaves directly, by a `direct` rule, a `direct` `final` or a
group that falls back to `direct` or offers it, has only the IPv6 of the
network the device is on. While the default interface has no global IPv6
address, or the app can't tell, the app refuses IPv6 to the IPs of those
rules, `ip:private` aside, and answers no AAAA for their domains, so apps
use IPv4. Set `ipv6: false` for a network that has an address but no
working IPv6, and `ipv6: true` to never refuse. Nodes with `ipv6: false`
are refused IPv6 the same way, always.

AAAA answers follow the domains of `rules` and `final`, whichever DNS
server answers. What an earlier rule sends where IPv6 works keeps it, as far
as the rule is known at that point: a name's lookup knows only domains, and
a connection's first packet only IPs, ports and networks. So a rule matching
IPs or ports ahead of one matching domains leaves its domains without AAAA,
and a rule matching domains ahead of one matching IPs leaves its IPs
refused.

At `info` and `debug`, sing-box, in the app or on a node, logs every
destination it connects to. The client's level reaches every user's app with the next
subscription update; raise it for diagnosis and lower it afterwards.

### `client.groups.<name>`

| Field | Default | Description |
| --- | --- | --- |
| `nodes` | `all` | members: `all`, `<tag>`, or `!<tag>` (without the tag) |
| `default` | `first`, or `auto` with `auto` | the preselected member: `first`, `auto`, `direct`, or an outbound tag such as `fr-reality`; users who can't use that tag get `first` |
| `include_direct` | `false` | also offer `direct` |
| `auto` | `false` | add a member, `<group>-auto`, that tests the others and uses the fastest working one |
| `fallback` | — | a group or `direct` to use when the user has no members here |

Every node a user may use contributes one member per protocol, tagged
`<node>-reality`, `<node>-hysteria2`, `<node>-naive`. `direct` is reserved.
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

Users can't connect to the node's private and loopback addresses, so they
can't reach its own services or network: sing-box nodes refuse them before
the node's rules, and xray's freedom outbound refuses them itself.

`ip:` and `geoip:` match the addresses of domains too, except on sing-box
nodes chaining to another: they leave domains to the upstream, so their IP
rules match only connections to IP addresses. Domains they send `direct`
are still resolved there and refused if private.

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
| `geosite` | `geosite:category-ru`, a code of the [rule data](#rule_data); `geosite:google@cn` keeps its domains with the attribute `cn`, and several (`@a@b`) must all be there, as xray reads them |
| `geoip` | `geoip:ru`, a code of the [rule data](#rule_data) |
| `domain`, `domain_suffix`, `domain_keyword` | `domain_suffix:example.com` |
| `ip` | `ip:10.0.0.0/8`, or `ip:private` for private and loopback ranges |
| `port` | `port:443` |
| `network` | `network:udp` (`tcp`, `udp`, `icmp`) |
| `protocol` | `protocol:bittorrent` (`tls`, `http`, `quic`, `bittorrent`); on nodes, after a `sniff` rule |

Hosting providers act on abuse complaints, which torrents shared through a
node attract. To refuse the torrent traffic sniffing recognizes (encrypted
or obfuscated BitTorrent can get past it):

```yaml
rules:
  - { action: sniff }
  - { match: [protocol:bittorrent], action: reject }
```

## `rule_data`

Where the data of `geoip:` and `geosite:` conditions comes from. Every node
and client profile is built from the same data, so the countries a client
routes by are those its node goes by; a node refusing `geoip:ru` won't get
the Russian traffic a client takes for foreign.

```yaml
rule_data: runetfreedom           # both kinds from one preset (the default)

rule_data:
  geoip: dbip                     # or each kind on its own
  geosite: https://example.org/geosite.dat
```

| Preset | geoip | geosite |
| --- | --- | --- |
| `runetfreedom` | [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) | the same |
| `loyalsoldier` | [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | the same |
| `v2fly` | [v2fly/geoip](https://github.com/v2fly/geoip) | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) |
| `dbip` | [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) | — |

A URL must be `https://`: a `geoip.dat` or, for geoip, a MaxMind-format
`.mmdb`, maybe gzipped; a `geosite.dat` for geosite. In a `.mmdb`, a network
belongs to the country it's located in, else the one it's registered in.
Where the URL's server has `<URL>.sha256sum`, as GitHub releases of rule data
usually do, the download must match it.

princo builds each engine's rule sets from the data, keeping only the codes
used: `<tag>.srs` for sing-box nodes, `geoip.dat` and `geosite.dat` for xray
nodes. Client profiles download theirs from the subscription site, which
serves the files of the node hosting it; without a `subscription`, they get
SagerNet's, which may tell countries apart differently. `princo deploy`
downloads the latest data; on NixOS presets come from nixpkgs or princo's
pins, and a URL needs `services.princo.ruleData` (see the
[deployment guide](deployment.md#nixos)).

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
| `default_resolver` | resolves the host names of DNS servers and outbounds; what users connect to goes through `final` and `rules` |
| `strategy` | `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` |
| `optimistic` | answer from an expired cache while refreshing |
| `rules` | `{ match: [...], server: <name> }`; domain conditions only |

A node queries its servers directly, not through its `egress`: a stalled
WARP or upstream must not break the lookups the node itself needs, such as
the REALITY handshake target.

## Engines

| Protocol | sing-box | xray |
| --- | --- | --- |
| `reality` | yes | yes |
| `xhttp` | no | yes |
| `hysteria2` | yes | no |
| `naive` | yes | no |

On xray nodes:

- DNS servers can't be `tls://`; their host names are resolved by the
  system, as xray has no `resolver` per server.
- `network:icmp` can't be matched.
- `action: sniff` turns on sniffing for the whole inbound, so every rule
  sees the sniffed domain, wherever the `sniff` rule stands.

Users' apps get the same subscription whatever engine the nodes run.

## `subscription`

| Field | Description |
| --- | --- |
| `node` | the node that serves the site |
| `domains` | its domains; each needs a DNS record pointing at that node, and a [certificate](#certificates) |

Each user gets `https://<domain>/<token>/`, where the token comes from
their UUID: share links for most apps, the profile for sing-box apps, and
a QR page at `/qr`. Apps that read subscription headers name the profile
after the domain, link to the QR page and refresh it daily.
`princo render --user <name> --links` prints them for the first domain.
Under the token:

| Path | Serves |
| --- | --- |
| `/` | the share links, or the sing-box profile to sing-box apps |
| `/base64` | the share links, whatever the app |
| `/sing-box` | the sing-box profile for the apps |
| `/sing-box/<platform>` | the sing-box profile for a [platform](#platforms) |
| `/qr` | a page with the links as QR codes |

Tokens stay stable across renders; changing a user's UUID changes their
subscription URL.

Every domain serves each user the same paths, and what it serves names
that domain alone: its links, QR pages and the rule set URLs in its
profiles. A user who reached the site through one domain never needs
another, so a second domain keeps the site working where the first is
blocked, and an old domain's links keep working after a new one is added:

```yaml
subscription:
  node: nl
  domains:
    - static.example.net    # the links princo prints
    - subs.example.com      # links users already have
```

Any of the domains can point at another host that passes its connections on,
as a node's [`passthrough`](#passthrough) does: a node in the users'
country forwarding `static.example.net` to the subscription node's IP on
443 makes the site reachable where that node's address is blocked, without
its files or keys leaving the subscription node. The forwarding host can't
answer HTTP-01 for the name, so cover it with a DNS-01
[certificate](#certificates).
Deploy the subscription node after changing users or their access so its
published profiles are updated.

### Platforms

Profiles for the apps work wherever the apps run. A platform's profile
also uses what only that platform has; `princo render --user <name>
--platform <platform>` prints it.

| Platform | sing-box |
| --- | --- |
| `linux` | sing-box running as a service, on a router or a desktop: TCP is redirected in the kernel with nftables (`auto_redirect`), faster than the TUN stack, and on a router that takes in the LAN's traffic |

## `monitor`

A GUI panel watches whether it reaches its nodes. That misses what users
notice first: an address blocked from their country, or a WARP account that
stopped passing traffic. With `monitor`, each node checks itself on a timer
and reports when something changes:

```yaml
monitor:
  notify:
    ops: { type: telegram }   # the bot and the chat from the secrets
  reach:
    - from: domestic          # nodes with this tag check that they reach the others
  interval: 2m
```

| Field | Default | Description |
| --- | --- | --- |
| `notify` | — | required: the [channels](#notify) to report to, by a name of your choosing |
| `reach` | — | [which nodes check that they reach which](#reach) |
| `interval` | `2m` | how often a node runs its checks; a minute at least |
| `confirm` | `2` | how many runs in a row must find a check changed before it is reported; `1` reports at once, a lost packet included |
| `certificate_days` | `14` | how many days before a certificate expires to report it |

### `notify`

Each channel has a name and a `type`. Every channel hears of every change,
each on its own: one that couldn't be reached gets what it missed on the
next run, without the others hearing it twice. A channel pointed at another
chat or URL is told the current failures anew.

```yaml
monitor:
  notify:
    ops: { type: telegram }
    family: { type: telegram, chat: "@family_vpn" }
    pager: { type: webhook }
```

`type: telegram` writes to a chat through a bot:

| Field | Default | Description |
| --- | --- | --- |
| `token` | `monitor/<channel>/token` | *secret*: the bot's token, from [@BotFather](https://t.me/BotFather) |
| `chat` | `monitor/<channel>/chat` | *secret*: the chat's ID, or `@channel`; the bot must be allowed to write there |
| `api` | `https://api.telegram.org` | another Bot API address over HTTPS, such as your own relay, for nodes that can't reach Telegram |

`type: webhook` posts JSON to a URL, for anything else: a chat's incoming
webhook that reads `text`, or a script of yours:

| Field | Default | Description |
| --- | --- | --- |
| `url` | `monitor/<channel>/url` | *secret*: where to post; an answer outside 2xx counts as not delivered |

Either type takes `via`, for the nodes that can't reach the channel, as
Telegram can't be reached from some countries:

| Field | Default | Description |
| --- | --- | --- |
| `via` | — | the nodes that reach the channel: a [tag](#nodesname), `!tag` or `all`. The others send their reports through them |

```yaml
monitor:
  notify:
    ops: { type: telegram, via: "!domestic" }
```

A node `via` selects reports on its own. Every other node reports through
the selected ones that serve `reality`, over the tunnel a
[chain](#egress) uses but with its own UUID, the *secret*
`nodes/<node>/monitor`; there the reports leave directly, whatever the
node's `egress`. A run tries up to three of them, so the report that one
is blocked leaves through another: first those it can still
[reach](#reach), and of them those no report has failed to leave through.

The reports enter the tunnel through a proxy of the node's engine on
`127.0.0.1:8447`, behind that UUID as its password.

`via` doesn't help a node whose engine is down, or one cut off from every
node it selects. Have the others watch it: `reach: [{ from: "!domestic", to: domestic }]`.

The body a webhook gets:

```json
{
  "node": "ru",
  "text": "princo node ru\n🔴 Can't reach node us: connecting to 203.0.113.7:443: timed out",
  "changes": [
    {
      "check": "reach/us",
      "down": true,
      "detail": "connecting to 203.0.113.7:443: timed out",
      "text": "🔴 Can't reach node us: connecting to 203.0.113.7:443: timed out"
    }
  ]
}
```

`text` is the whole report as a person reads it. `check` is `engine`,
`warp`, `certificate/<name>`, `served/<server name>` or `reach/<node>`.

### `reach`

A list of rules: the nodes `from` selects check that they reach the ones
`to` selects, themselves aside. Both take a [tag](#nodesname), `!tag` for
the nodes without it, or `all`; `to` is `all` when omitted.

```yaml
monitor:
  reach:
    - from: domestic              # every other node, from inside the country
    - { from: eu, to: "!eu" }     # and the rest of the world from Europe
```

### Checks

Every node checks:

- **the engine**: that `princo.service` runs;
- **certificates**: that each one the node serves has `certificate_days`
  left or more. ACME renews with a month left, so two weeks means renewal
  keeps failing;
- **served certificates**: that Naive and the subscription site present
  the certificate on disk, asked on the node itself. One presenting another
  missed a renewal and goes on with the old certificate. Hysteria2, on UDP,
  isn't asked;
- **WARP**, with `egress: warp` on sing-box: that a request through it gets an
  answer. The check goes through the engine's API, so the node needs the
  secret `nodes/<node>/api`, which `princo secret gen` makes.

Nodes that a [`reach`](#reach) rule selects also check **reachability**:
they connect to TCP 443 of the rule's nodes and, where one serves Reality or
Naive, complete a TLS handshake under that name, as a client's first packets
would. Have a node inside the country your users connect from check the
others: this is the check that notices a node blocked there. The message says which step failed, the
connection or the handshake.

A check changes state once `confirm` runs in a row find it so, and each
channel hears of each change once, including the recovery:

```text
princo node ru
🔴 Can't reach node us: connecting to 203.0.113.7:443: timed out

princo node ru
🟢 Node us is reachable again, after 2h13m
```

A report a channel didn't take is sent again on the next run. To see what a
node finds now, run `princo host monitor --dry-run` on it; see
[Monitoring](deployment.md#monitoring).

What it doesn't see:

- One node sees one network. Blocks differ by operator and region, so a
  node in a data center may reach what a mobile operator's users can't.
- Hysteria2 is not probed: UDP 443 answers nothing to a stranger. A node
  serving only Hysteria2 is left out of the reachability checks.
- A blocked protocol, where the address and the name still answer.
- xray nodes' WARP: xray has no API to test it through.
- A node that is down doesn't report itself. A `from` node reports the
  others; tag two, and they report each other.

## `certificates`

Hysteria2's `address`, Naive's `domain` and the subscription domains need
certificates. By default each node gets one per domain from Let's Encrypt
over HTTP-01, which needs TCP 80 open. Every certificate is published in
[Certificate Transparency](https://certificate.transparency.dev/) logs,
such as crt.sh, so each such domain is public the day it is issued.
`certificates` covers domains otherwise: a wildcard over DNS-01 keeps the
names under it out of the logs, and a certificate issued elsewhere, such as
a bought one or Cloudflare's Origin CA, comes from secrets.

```yaml
certificates:
  wild:
    domains: [example.com, "*.example.com"]
    acme:
      dns: cloudflare
      env: { CLOUDFLARE_DNS_API_TOKEN: !secret certificates/cloudflare }
  subs:
    domains: [subs.example.com]
    file: {}          # certificates/subs/fullchain and certificates/subs/key
```

| Field | Description |
| --- | --- |
| `domains` | the domains it covers; `*.example.com` covers one label under `example.com`, not `example.com` itself or `a.b.example.com` |
| `acme` | each node that needs it issues it from Let's Encrypt and renews it: over HTTP-01, or with `dns` over DNS-01 |
| `acme.dns` | a [lego DNS provider](https://go-acme.github.io/lego/dns/), such as `cloudflare` or `route53`; wildcards need one |
| `acme.env` | the provider's credentials, as the environment variables lego's page for it lists; values may be `!secret`, each one line without `'` |
| `file` | a certificate issued elsewhere |
| `file.fullchain` | *secret*, `certificates/<name>/fullchain`: the certificate in PEM, followed by its chain |
| `file.key` | *secret*, `certificates/<name>/key`: its private key in PEM |

A domain takes the entry that lists it, else one whose wildcard covers it,
else a certificate of its own over HTTP-01. One domain can be in one entry
only. Names of entries are like node names; a node keeps a certificate in
`/var/lib/princo/certs/<name>`.

The engine and the subscription site can serve the same certificate: a
subscription domain under the wildcard that covers Naive's takes it too.
The node keeps it once, and both load it anew when it is renewed.

For Cloudflare, give lego an API token with Zone / DNS / Edit permission
on the zone alone. princo checks a `file` certificate against its key and
its domains when it renders, but not its expiry: renew it yourself before
it lapses. Cloudflare's Origin CA certificates are trusted by Cloudflare
alone, so they suit a proxied domain, such as the subscription site behind
Cloudflare, and not the domains clients connect to directly.

## `secrets`

Maps logical secret paths to storage locations: `sops:<file>` or
`age:<file>`, optionally followed by `#<key>`. File paths are relative to
the config file that defines the mapping.

The most specific match wins, regardless of order: an exact path takes
precedence over a wildcard pattern; among wildcard patterns, the longest
prefix wins. Unmatched paths use `secrets.age` next to the config file, or
next to the last file when [merging several files](#several-files).

```yaml
secrets:
  users/*: sops:../secrets/shared.yaml#vless_uuid_*
  shared/hysteria2_obfs: sops:../secrets/shared.yaml#hysteria2_obfs_password
  nodes/fr/*: sops:../secrets/fr.yaml
  nodes/fr/warp/*: sops:../secrets/warp.yaml  # wins over nodes/fr/* for these
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
| `princo secret list [--check]` | list the secrets the config uses, where each is stored and which config file maps it; `--check` decrypts and fails on ones without a value |
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
`DIR/users/alice`. `princo plan --node <name>` lists the names in its
`secrets[].file` fields.

Only the secrets needed for the node's runtime files must be present. A node
serving subscriptions also needs credentials used to generate its users'
profiles. See the [NixOS guide](deployment.md#nixos) for sops-nix and custom
secret directories.

## Several files

Repeat `--config` to merge files in the order given. For example, keep
protocols and routing in a public repository, and addresses, users and
secret mappings in a private one. Later files override earlier values.

```sh
princo -c vpn/princo.yaml -c ../fleet/princo.yaml plan --node fr
```

```yaml
# vpn/princo.yaml, public
princo: v1
defaults:
  reality: { server_name: www.samsung.com }
nodes:
  fr: { reality: {}, hysteria2: {} }
```

```yaml
# ../fleet/princo.yaml, private
princo: v1
nodes:
  fr:
    address: fr.example.com
    reality: { short_id: 1a3287df, public_key: rTfvDnYUF2iyaHAreWAuNEJ2MipD-PGBiDysUvNJHjM }
users:
  alice: {}
secrets:
  users/*: sops:secrets/shared.yaml#vless_uuid_*
  nodes/fr/*: sops:secrets/fr.yaml
```

### Merge rules

- Mappings merge key by key at every depth.
- Lists and scalar values replace the earlier value. For example, a later
  `rules` list replaces the entire earlier list; rules are not appended.
- Null values, including an empty `users:`, leave earlier values unchanged.
  To remove a key, remove it from every file that defines it.
- Existing keys keep their order; new keys are appended in the order they
  appear. This preserves the order of nodes, users and client groups.
- YAML anchors, aliases and `<<` merge keys are resolved within each file
  before the files are merged. An alias keeps its original value even if
  a later file overrides the field containing its anchor.

Each file must declare `princo: v1` and use known fields. Fleet validation
runs on the merged result, so individual files may describe only part of
the fleet.

### Secret locations

Each `secrets:` mapping resolves file paths relative to the config file
that defines it. If a later file replaces the same pattern, its directory
is used instead. A null value preserves the earlier mapping and directory.
More specific patterns still win, regardless of which file defines them.

The default `secrets.age` and the recipients file (`.princo/recipients`,
falling back to `recipients`) are next to the last config file.

`princo plan` reports each secret's location in `source.file`, relative to
the config file identified by `source.config`. This index starts at 0 and
follows the order of the `--config` flags.

### Editing commands

- `user add` adds the user to the last config file.
- `user remove` removes the user from every file that defines them, dropping
  any `users:` section left empty.
- `secret gen` updates an existing Reality public key in the file that
  supplies its effective value. If the key is absent, it prints the public
  key for you to add. If a YAML merge key prevents a safe edit, generation
  stops before replacing the private key.
- `init` accepts only one config file.

On NixOS, pass the files as a list to
[`services.princo.config`](deployment.md#nixos).

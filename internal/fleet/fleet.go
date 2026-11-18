// Package fleet is the resolved model of princo.yaml: defaults applied,
// secrets substituted, references checked. Engines render from it.
package fleet

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// Fleet is everything princo knows about the VPN.
type Fleet struct {
	// Nodes and Users are sorted by name.
	Nodes        []*Node
	Users        []*User
	Client       Client
	Subscription *Subscription
	// Certificates are princo.yaml's, in its order.
	Certificates []*Certificate
	RuleData     RuleData
	// Monitor is nil when the nodes don't check themselves.
	Monitor *Monitor

	nodes map[string]*Node
	users map[string]*User
}

// Node looks up a node by name.
func (f *Fleet) Node(name string) (*Node, bool) {
	n, ok := f.nodes[name]
	return n, ok
}

// User looks up a user by name.
func (f *Fleet) User(name string) (*User, bool) {
	u, ok := f.users[name]
	return u, ok
}

// UsersOf returns the users allowed on n, sorted by name.
func (f *Fleet) UsersOf(n *Node) []*User {
	var out []*User
	for _, u := range f.Users {
		if slices.Contains(u.Nodes, n) {
			out = append(out, u)
		}
	}
	return out
}

// ChainsInto returns the nodes whose egress is n, sorted by name.
func (f *Fleet) ChainsInto(n *Node) []*Node {
	var out []*Node
	for _, m := range f.Nodes {
		if m.Egress.Node == n {
			out = append(out, m)
		}
	}
	return out
}

// Node is one server.
type Node struct {
	Name      string
	SSH       string
	Address   string
	Engine    string
	ACMEEmail string
	Tags      []string
	IPv6      bool

	// Enabled protocols; nil when off.
	Reality   *Reality
	Hysteria2 *Hysteria2
	Naive     *Naive

	Egress Egress
	// Warp holds the WARP credentials when Egress is EgressWarp.
	Warp *Warp
	// ChainUUID is this node's identity on its upstream when Egress.Node is set.
	ChainUUID string
	// MonitorVia are the nodes this one sends its monitor's reports
	// through, to any channel, sorted by name. MonitorUUID is its identity
	// there, and the password of its own proxy to them.
	MonitorVia  []*Node
	MonitorUUID string

	DNS         *DNS
	Rules       []Rule
	Passthrough []Passthrough
	// Log is the engine's log level, one of LogLevels.
	Log string
	// Stats has princo stats read the engine's connections.
	Stats bool
	// API, when set, is the engine's API at 127.0.0.1:APIPort, which
	// princo stats and the monitor's WARP check talk to.
	API *API

	// ServesSubscription is set on the node hosting the subscription site.
	ServesSubscription bool
}

// Protocols lists the protocols n serves, by their names in princo.yaml.
func (n *Node) Protocols() []string {
	var out []string
	if n.Reality != nil {
		out = append(out, "reality")
	}
	if n.Hysteria2 != nil {
		out = append(out, "hysteria2")
	}
	if n.Naive != nil {
		out = append(out, "naive")
	}
	return out
}

// HasTag reports whether the node carries tag.
func (n *Node) HasTag(tag string) bool { return slices.Contains(n.Tags, tag) }

// MuxRealityPort and MuxNaivePort are the loopback ports behind the SNI
// multiplexer on TCP 443.
const (
	MuxRealityPort = 8444
	MuxNaivePort   = 8445
)

// APIPort is the engine's API, on 127.0.0.1.
const APIPort = 8446

// MonitorPort is the engine's SOCKS proxy for the monitor's reports, on
// 127.0.0.1. Its user names the node a connection leaves through.
const MonitorPort = 8447

// MonitorAccount is the name n logs in with on the nodes it sends its
// reports through.
func MonitorAccount(n *Node) string { return "monitor:" + n.Name }

type API struct {
	// Secret keeps the host's other users out of the engine.
	Secret string
}

// Monitor is the checks each node runs on itself every Interval, telling
// the channels of Notify what changed.
type Monitor struct {
	// Notify are the channels, sorted by name.
	Notify   []Channel
	Interval time.Duration
	// Confirm is how many runs in a row change a check's state.
	Confirm int
	// CertificateDays is how long before a certificate expires its check
	// fails.
	CertificateDays int
	Reach           []Reach
}

// Channel is where reports go: Telegram or Webhook, whichever is set.
type Channel struct {
	Name     string
	Telegram *Telegram
	Webhook  *Webhook
	// Via, when set, selects the nodes that reach the channel themselves;
	// the others send through them.
	Via *Selector
}

type Telegram struct {
	API   string
	Token string
	Chat  string
}

// Webhook takes the reports as JSON, posted to URL.
type Webhook struct {
	URL string
}

// Reach has the nodes From selects check that they reach those of To.
type Reach struct {
	From, To Selector
}

const DefaultTelegramAPI = "https://api.telegram.org"

// The monitor's defaults, and the shortest interval that leaves a run time
// to end before the next.
const (
	DefaultMonitorInterval = 2 * time.Minute
	MinMonitorInterval     = time.Minute
	DefaultMonitorConfirm  = 2
	// ACME renews with a month left: by then renewal has failed for weeks.
	DefaultCertificateDays = 14
)

// MonitorsWarp tells whether the monitor checks n's WARP, which takes an
// engine with an API: sing-box.
func (f *Fleet) MonitorsWarp(n *Node) bool {
	return f.Monitor != nil && n.Egress.Kind == EgressWarp && n.Engine == "sing-box"
}

// Reaches lists the nodes n checks that it reaches, sorted by name: those
// the monitor's Reach rules select for it, n aside.
func (f *Fleet) Reaches(n *Node) []*Node {
	if f.Monitor == nil {
		return nil
	}
	var out []*Node
	for _, m := range f.Nodes {
		if m != n && slices.ContainsFunc(f.Monitor.Reach, func(r Reach) bool { return r.From.Matches(n) && r.To.Matches(m) }) {
			out = append(out, m)
		}
	}
	return out
}

// Via lists the nodes n sends its reports to ch through, sorted by name:
// those ch.Via selects whose Reality n's engine can connect to. None when
// n is one of them, and sends on its own.
func (f *Fleet) Via(n *Node, ch Channel) []*Node {
	if ch.Via == nil || ch.Via.Matches(n) {
		return nil
	}
	var out []*Node
	for _, m := range f.Nodes {
		if !ch.Via.Matches(m) {
			continue
		}
		if _, ok := m.Dial(n.Engine); ok {
			out = append(out, m)
		}
	}
	return out
}

// MonitorsInto lists the nodes that send their reports through n, sorted
// by name.
func (f *Fleet) MonitorsInto(n *Node) []*Node {
	var out []*Node
	for _, m := range f.Nodes {
		if slices.Contains(m.MonitorVia, n) {
			out = append(out, m)
		}
	}
	return out
}

// Mux reports whether TCP 443 is shared through the SNI multiplexer, which
// is needed as soon as anything besides VLESS-Reality wants it.
func (n *Node) Mux() bool {
	return n.Naive != nil || len(n.Passthrough) > 0 || n.ServesSubscription
}

type Reality struct {
	ServerName string
	// TargetHost:TargetPort is the site that takes the TLS handshakes of
	// whoever isn't a client: ServerName's, or a local one for self-steal.
	TargetHost string
	TargetPort int
	ShortID    string
	PublicKey  string
	PrivateKey string
	// Transports are the ways in, at least one, in the order of
	// TransportKinds.
	Transports []Transport
}

// The Reality transports, by their names in princo.yaml.
const (
	// TransportTCP is VLESS on the TLS stream itself, with XTLS Vision.
	TransportTCP   = "tcp"
	TransportGRPC  = "grpc"
	TransportXHTTP = "xhttp"
)

// TransportKinds lists the transports, the preferred first: what connects
// to a node takes the first of the node's that it speaks.
var TransportKinds = []string{TransportTCP, TransportGRPC, TransportXHTTP}

// Transport is one way into a node's Reality inbound.
type Transport struct {
	// Kind is one of TransportKinds.
	Kind string
	// ServiceName is gRPC's.
	ServiceName string
	// Path is XHTTP's, and Mode its client's: auto, packet-up, stream-up
	// or stream-one.
	Path string
	Mode string
}

// Protocol names Reality over t among a node's protocols: reality for
// tcp, the default, and reality-<kind> for the others.
func (t Transport) Protocol() string {
	if t.Kind == TransportTCP {
		return "reality"
	}
	return "reality-" + t.Kind
}

// Vision reports whether accounts on t use the XTLS Vision flow, which
// needs the TLS stream to itself.
func (t Transport) Vision() bool { return t.Kind == TransportTCP }

// The engines, by their names in princo.yaml.
const (
	SingBox = "sing-box"
	Xray    = "xray"
)

// ClientEngine renders client profiles whatever engine the servers run:
// sing-box profiles are what the apps import.
const ClientEngine = SingBox

// engineTransports are the Reality transports each engine speaks, both
// serving them and connecting to another node. A transport an engine
// learns is added here and to its renderer.
var engineTransports = map[string][]string{
	SingBox: {TransportTCP, TransportGRPC},
	Xray:    {TransportTCP, TransportGRPC, TransportXHTTP},
}

// EngineTransports lists the Reality transports engine speaks.
func EngineTransports(engine string) []string { return engineTransports[engine] }

// engineFallbacks are the transports each engine serves beside tcp on the
// same port, one at a time: what isn't VLESS on the TLS stream falls back
// to them.
var engineFallbacks = map[string][]string{
	Xray: {TransportXHTTP},
}

// MemberID identifies a node's protocol in princo.yaml and in server
// configs, as fr/reality-grpc: no name has a slash. What apps show for it
// is Client.Name.
func MemberID(n *Node, protocol string) string { return n.Name + "/" + protocol }

// Relayed is a member, by its ID or its name, as reached through relay:
// fr/reality@ru or fr-reality@ru. Nothing else has an @.
func Relayed(member string, relay *Node) string { return member + "@" + relay.Name }

// ClientProtocols names what n offers the client profiles, in the order
// of their outbounds: Reality by the transports the client engine speaks,
// then the rest. None for a node that is in share links only.
func (n *Node) ClientProtocols() []string { return n.protocols(n.Dials(ClientEngine)) }

// LinkProtocols names everything n has a share link for, in their order:
// Reality by every transport, as an app of another engine may speak what
// the profiles' doesn't.
func (n *Node) LinkProtocols() []string {
	if n.Reality == nil {
		return n.protocols(nil)
	}
	return n.protocols(n.Reality.Transports)
}

// protocols names Reality over each of ts, then n's other protocols.
func (n *Node) protocols(ts []Transport) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Protocol())
	}
	if n.Hysteria2 != nil {
		out = append(out, "hysteria2")
	}
	if n.Naive != nil {
		out = append(out, "naive")
	}
	return out
}

// Dials lists the transports of n's Reality that engine connects by, the
// preferred first; none without Reality.
func (n *Node) Dials(engine string) []Transport {
	if n.Reality == nil {
		return nil
	}
	var out []Transport
	for _, t := range n.Reality.Transports {
		if slices.Contains(engineTransports[engine], t.Kind) {
			out = append(out, t)
		}
	}
	return out
}

// Dial is the transport whatever runs engine connects to n by where it
// takes one: a chain hop, a monitor's reports or a relayed connection.
func (n *Node) Dial(engine string) (Transport, bool) {
	ts := n.Dials(engine)
	if len(ts) == 0 {
		return Transport{}, false
	}
	return ts[0], true
}

// Upstreams are the nodes n connects to by Reality: its chain's next hop,
// then those its monitor reports through.
func (n *Node) Upstreams() []*Node {
	var out []*Node
	if up := n.Egress.Node; up != nil {
		out = append(out, up)
	}
	return append(out, n.MonitorVia...)
}

// ServesTogether reports whether engine serves ts on one port: one
// transport it speaks, or tcp and one it falls back to.
func ServesTogether(engine string, ts []Transport) bool {
	for _, t := range ts {
		if !slices.Contains(engineTransports[engine], t.Kind) {
			return false
		}
	}
	switch len(ts) {
	case 1:
		return true
	case 2:
		return ts[0].Kind == TransportTCP && slices.Contains(engineFallbacks[engine], ts[1].Kind)
	default:
		return false
	}
}

// Account is who logs in to a node's Reality inbound.
type Account struct {
	Name string
	UUID string
}

// Accounts lists who connects to n by t: its users, then the chain hops
// and the monitors of the nodes that reach it by t. Those log in like
// users, as no user can be named.
func (f *Fleet) Accounts(n *Node, t Transport) []Account {
	var out []Account
	for _, u := range f.UsersOf(n) {
		out = append(out, Account{Name: u.Name, UUID: u.UUID})
	}
	by := func(m *Node) bool {
		d, ok := n.Dial(m.Engine)
		return ok && d.Kind == t.Kind
	}
	for _, m := range f.ChainsInto(n) {
		if by(m) {
			out = append(out, Account{Name: "chain:" + m.Name, UUID: m.ChainUUID})
		}
	}
	for _, m := range f.MonitorsInto(n) {
		if by(m) {
			out = append(out, Account{Name: MonitorAccount(m), UUID: m.MonitorUUID})
		}
	}
	return out
}

type Hysteria2 struct {
	Masquerade string
	// Obfs is salamander, gecko or empty for none.
	Obfs         string
	ObfsPassword string
}

type Naive struct {
	Domain string
}

type Warp struct {
	PrivateKey string
	IPv4       string
	IPv6       string
	// Reserved is the account's client ID as 3 bytes, when it needs one.
	Reserved []int
	// Host and Port are the WARP peer.
	Host string
	Port int
}

// DefaultWarpEndpoint is Cloudflare's WARP peer.
const DefaultWarpEndpoint = "engage.cloudflareclient.com:2408"

type EgressKind int

const (
	EgressDirect EgressKind = iota
	EgressWarp
	// EgressNode forwards to another node over VLESS-Reality: a chain hop.
	EgressNode
)

type Egress struct {
	Kind EgressKind
	Node *Node // for EgressNode
}

// Passthrough hands TLS connections for Host on TCP 443 to Target.
type Passthrough struct {
	Host   string
	Target string
}

type User struct {
	Name string
	UUID string
	// Nodes the user may use, in subscription order.
	Nodes []*Node
	// Client is the user's profile: Fleet.Client, or their own.
	Client *Client
}

type DNS struct {
	Servers         []DNSServer
	Final           string
	DefaultResolver string
	Strategy        string
	Optimistic      bool
	Rules           []DNSRule
}

type DNSServer struct {
	Name string
	// Type is udp, tcp, tls, https or quic.
	Type     string
	Server   string
	Port     int // 0 for the protocol default
	Path     string
	Via      string
	Resolver string
}

type DNSRule struct {
	Match  []Matcher
	Server string
}

// Rule actions.
const (
	ActionDirect = "direct"
	ActionReject = "reject"
	ActionSniff  = "sniff"
	// ActionVia sends traffic through Rule.Via (client groups only).
	ActionVia = "via"
)

type Rule struct {
	Match  []Matcher
	Action string
	Via    string
}

type Client struct {
	Groups []Group
	DNS    *DNS
	Rules  []Rule
	Final  string
	// Label is what apps show for a node's protocol: its outbound's tag
	// in a profile and its share link's name. A template of LabelFields.
	Label string
	// Log is the apps' log level, one of LogLevels.
	Log string
	// IPv6 says whether direct traffic can use IPv6; nil leaves it to the
	// profile, which checks the network it is on.
	IPv6 *bool
}

// DefaultLabel names a node's protocol as fr-reality-grpc.
const DefaultLabel = "{node}-{protocol}"

// LabelFields are what a label is made of.
var LabelFields = []string{"node", "protocol", "user"}

// Name is what apps show u for n's protocol: c.Label filled in.
func (c *Client) Name(u *User, n *Node, protocol string) string {
	label := cmp.Or(c.Label, DefaultLabel)
	return strings.NewReplacer("{node}", n.Name, "{protocol}", protocol, "{user}", u.Name).Replace(label)
}

// LogLevels are the log levels, most verbose first; engines map them to
// their own names. LogNone turns logging off.
var LogLevels = []string{"debug", "info", LogWarn, "error", LogNone}

const (
	// LogWarn is the default: errors and warnings, no destinations.
	LogWarn = "warn"
	LogNone = "none"
)

// Group is a selector in the client app.
type Group struct {
	Name string
	// Members selects nodes by tag.
	Members Selector
	// Relay selects the nodes each member is also offered through, the
	// client connecting to the member inside its connection to the relay;
	// nil for none.
	Relay         *Selector
	Default       string // "first", "auto", "direct" or a member's ID
	IncludeDirect bool
	// Auto adds a member that picks the fastest working one.
	Auto bool
	// Fallback replaces the group where a user has no member nodes:
	// "direct" or another group.
	Fallback string
}

// Selector picks nodes by tag.
type Selector struct {
	All    bool
	Tag    string
	Negate bool
}

func (s Selector) Matches(n *Node) bool {
	if s.All {
		return true
	}
	return n.HasTag(s.Tag) != s.Negate
}

type Subscription struct {
	Node *Node
	// Domains each serve the site under their own name: its links, QR pages
	// and profiles name the domain they are served from. Lowercase.
	Domains []string
	// RuleSets says, by domain, how profiles served under it fetch their
	// rule sets.
	RuleSets map[string]RuleSetFetch
}

// RuleSetFetch is how a profile fetches its rule sets from the site.
type RuleSetFetch struct {
	// Direct fetches them without the proxy, as from where the domain is
	// reached directly; otherwise through the profile's final outbound.
	Direct bool
	// Relay is the node found forwarding the domain to the site's node by
	// passthrough, which made Direct; nil when none or when Set.
	Relay *Node
	// Set is when subscription.domains gave rule_sets rather than princo
	// inferring it.
	Set bool
}

// RuleSetsDirect reports whether profiles served under domain fetch their
// rule sets directly; false without a subscription or for another domain.
func (s *Subscription) RuleSetsDirect(domain string) bool {
	return s != nil && s.RuleSets[strings.ToLower(domain)].Direct
}

// Domain is the one princo prints links for, the first; empty without a
// subscription.
func (s *Subscription) Domain() string {
	if s == nil {
		return ""
	}
	return s.Domains[0]
}

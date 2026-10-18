// Package fleet is the resolved model of princo.yaml: defaults applied,
// secrets substituted, references checked. Engines render from it.
package fleet

import "slices"

// Fleet is everything princo knows about the VPN.
type Fleet struct {
	// Nodes and Users are sorted by name.
	Nodes        []*Node
	Users        []*User
	Client       Client
	Subscription *Subscription

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

	DNS         *DNS
	Rules       []Rule
	Passthrough []Passthrough

	// ServesSubscription is set on the node hosting the subscription site.
	ServesSubscription bool
}

// HasTag reports whether the node carries tag.
func (n *Node) HasTag(tag string) bool { return slices.Contains(n.Tags, tag) }

// Mux reports whether TCP 443 is shared through the SNI multiplexer, which
// is needed as soon as anything besides VLESS-Reality wants it.
func (n *Node) Mux() bool {
	return n.Naive != nil || len(n.Passthrough) > 0 || n.ServesSubscription
}

type Reality struct {
	ServerName string
	ShortID    string
	PublicKey  string
	PrivateKey string
}

type Hysteria2 struct {
	Masquerade   string
	ObfsPassword string
}

type Naive struct {
	Domain string
}

type Warp struct {
	PrivateKey string
	IPv4       string
	IPv6       string
}

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
}

// Group is a selector in the client app.
type Group struct {
	Name string
	// Members selects nodes by tag.
	Members       Selector
	Default       string // "first", "direct" or an outbound tag
	IncludeDirect bool
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
	Node   *Node
	Domain string
}

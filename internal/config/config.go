// Package config is the literal shape of princo.yaml: what the user wrote,
// before defaults are applied and secrets resolved (see package fleet).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/dfjay/princo/internal/secrets"
)

// Config is the top level of princo.yaml.
type Config struct {
	Princo       string               `yaml:"princo"`
	Defaults     Defaults             `yaml:"defaults"`
	Nodes        Ordered[Node]        `yaml:"nodes"`
	Users        Ordered[User]        `yaml:"users"`
	Client       Client               `yaml:"client"`
	Subscription *Subscription        `yaml:"subscription"`
	Certificates Ordered[Certificate] `yaml:"certificates"`
	RuleData     *RuleData            `yaml:"rule_data"`
	Secrets      Ordered[string]      `yaml:"secrets"`

	// The index of the file Merge took each secrets: pattern from.
	secretFiles map[string]int
	// client: and each user's client:, as written, for UserClient.
	clientNode  *yaml.Node
	userClients map[string]*yaml.Node
}

// UserClient returns the profile of the named user: client: with the
// user's own client: merged over it as Merge merges files.
func (c *Config) UserClient(name string) (Client, error) {
	over := c.userClients[name]
	if over == nil {
		return c.Client, nil
	}
	if c.clientNode != nil {
		over = mergeNode(c.clientNode, over)
	}
	var out Client
	err := over.Decode(&out)
	return out, err
}

// SecretMappings returns the secrets: block in document order.
func (c *Config) SecretMappings() []secrets.Mapping {
	var out []secrets.Mapping
	for pattern, target := range c.Secrets.All() {
		out = append(out, secrets.Mapping{Pattern: pattern, Target: target, File: c.secretFiles[pattern]})
	}
	return out
}

// Defaults are inherited by every node. Protocol blocks here only supply
// default values; a node enables a protocol by having its own block.
type Defaults struct {
	Engine    string     `yaml:"engine"`
	ACMEEmail string     `yaml:"acme_email"`
	Reality   *Reality   `yaml:"reality"`
	Hysteria2 *Hysteria2 `yaml:"hysteria2"`
	XHTTP     *XHTTP     `yaml:"xhttp"`
	Egress    string     `yaml:"egress"`
	DNS       *DNS       `yaml:"dns"`
	Rules     []Rule     `yaml:"rules"`
	Log       string     `yaml:"log"`
	Stats     *bool      `yaml:"stats"`
}

// Node is one server. Unset fields inherit from Defaults; Rules, when
// present (even empty), replace the default rules entirely.
type Node struct {
	SSH         string          `yaml:"ssh"`
	Address     string          `yaml:"address"`
	Engine      string          `yaml:"engine"`
	ACMEEmail   string          `yaml:"acme_email"`
	Tags        []string        `yaml:"tags"`
	IPv6        *bool           `yaml:"ipv6"`
	Reality     *Reality        `yaml:"reality"`
	Hysteria2   *Hysteria2      `yaml:"hysteria2"`
	Naive       *Naive          `yaml:"naive"`
	XHTTP       *XHTTP          `yaml:"xhttp"`
	Warp        *Warp           `yaml:"warp"`
	Egress      string          `yaml:"egress"`
	DNS         *DNS            `yaml:"dns"`
	Rules       []Rule          `yaml:"rules"`
	Passthrough Ordered[string] `yaml:"passthrough"`
	Log         string          `yaml:"log"`
	Stats       *bool           `yaml:"stats"`
}

type Reality struct {
	ServerName string                 `yaml:"server_name"`
	Target     string                 `yaml:"target"`
	ShortID    string                 `yaml:"short_id"`
	PublicKey  string                 `yaml:"public_key"`
	PrivateKey *secrets.SecretOrPlain `yaml:"private_key"`
}

type Hysteria2 struct {
	Masquerade   string                 `yaml:"masquerade"`
	Obfs         string                 `yaml:"obfs"`
	ObfsPassword *secrets.SecretOrPlain `yaml:"obfs_password"`
}

type XHTTP struct {
	Path string `yaml:"path"`
	Mode string `yaml:"mode"`
}

type Naive struct {
	Domain string `yaml:"domain"`
}

type Warp struct {
	PrivateKey *secrets.SecretOrPlain `yaml:"private_key"`
	IPv4       *secrets.SecretOrPlain `yaml:"ipv4"`
	IPv6       *secrets.SecretOrPlain `yaml:"ipv6"`
	Reserved   []int                  `yaml:"reserved"`
	Endpoint   string                 `yaml:"endpoint"`
}

// DNS configures a resolver, on a server or in the client profile.
type DNS struct {
	Servers         Ordered[DNSServer] `yaml:"servers"`
	Final           string             `yaml:"final"`
	DefaultResolver string             `yaml:"default_resolver"`
	Strategy        string             `yaml:"strategy"`
	Optimistic      bool               `yaml:"optimistic"`
	Rules           []DNSRule          `yaml:"rules"`
}

type DNSServer struct {
	// Address is udp://IP, tls://host, https://host[/path] or a bare IP (UDP).
	Address string `yaml:"address"`
	// Via is a client group the queries go through.
	Via string `yaml:"via"`
	// Resolver is another server used to resolve this one's hostname.
	Resolver string `yaml:"resolver"`
}

type DNSRule struct {
	Match  []string `yaml:"match"`
	Server string   `yaml:"server"`
}

// Rule matches traffic and decides where it goes. Match entries are ORed.
type Rule struct {
	Match  []string `yaml:"match"`
	Action string   `yaml:"action"`
	Via    string   `yaml:"via"`
}

type User struct {
	// Nodes the user may use, in subscription order; nil means all.
	Nodes []string               `yaml:"nodes"`
	UUID  *secrets.SecretOrPlain `yaml:"uuid"`
	// Client overrides client: for this user; see Config.UserClient.
	Client *Client `yaml:"client"`
}

// Client describes the sing-box profile served to users.
type Client struct {
	Groups Ordered[Group] `yaml:"groups"`
	DNS    *DNS           `yaml:"dns"`
	Rules  []Rule         `yaml:"rules"`
	Final  string         `yaml:"final"`
	// Log is the apps' log level; above warn they log every destination.
	Log string `yaml:"log"`
}

// Group is a selector in the client app over some of the user's nodes.
type Group struct {
	// Nodes selects members by tag: "<tag>", "!<tag>" or "all".
	Nodes         string `yaml:"nodes"`
	Default       string `yaml:"default"`
	Auto          bool   `yaml:"auto"`
	IncludeDirect bool   `yaml:"include_direct"`
	Fallback      string `yaml:"fallback"`
}

type Subscription struct {
	Node   string `yaml:"node"`
	Domain string `yaml:"domain"`
}

// Certificate covers Domains, wildcards among them, from ACME or File.
// Domains no certificate covers get an ACME HTTP-01 one each.
type Certificate struct {
	Domains []string  `yaml:"domains"`
	ACME    *CertACME `yaml:"acme"`
	File    *CertFile `yaml:"file"`
}

// CertACME has each node issue the certificate: over DNS-01 with DNS, a
// lego provider whose credentials are in Env, else over HTTP-01.
type CertACME struct {
	DNS string                         `yaml:"dns"`
	Env Ordered[secrets.SecretOrPlain] `yaml:"env"`
}

// CertFile is a certificate issued elsewhere, in PEM.
type CertFile struct {
	Fullchain *secrets.SecretOrPlain `yaml:"fullchain"`
	Key       *secrets.SecretOrPlain `yaml:"key"`
}

// RuleData is where the geoip and geosite data of every node and client
// profile comes from: a preset or an https:// URL each. A plain string sets
// both.
type RuleData struct {
	GeoIP   string `yaml:"geoip"`
	Geosite string `yaml:"geosite"`
}

func (r *RuleData) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		r.GeoIP, r.Geosite = node.Value, node.Value
		return nil
	}
	type plain RuleData
	return decodeStrict(node, (*plain)(r))
}

// Parse decodes a princo.yaml document strictly: unknown fields anywhere
// are errors, and the schema version must be v1. Anchors, aliases and
// `<<` merge keys are resolved first, so they work in every section.
func Parse(data []byte) (*Config, error) {
	cfg, _, err := parse(data)
	return cfg, err
}

// parse is Parse that also returns the document with its aliases resolved.
func parse(data []byte) (*Config, *yaml.Node, error) {
	root, resolved, err := normalize(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse princo.yaml: %w", err)
	}
	if resolved { // otherwise errors keep the file's line numbers
		if data, err = yaml.Marshal(root); err != nil {
			return nil, nil, err
		}
	}
	cfg, err := decode(data, root)
	return cfg, root, err
}

// decode decodes data, whose document is root.
func decode(data []byte, root *yaml.Node) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse princo.yaml: %w", err)
	}
	switch cfg.Princo {
	case "v1":
		cfg.keepClientNodes(root)
		return &cfg, nil
	case "":
		return nil, fmt.Errorf("princo: required (set `princo: v1` at the top of the file)")
	default:
		return nil, fmt.Errorf("unsupported schema version %q (expected v1)", cfg.Princo)
	}
}

func (c *Config) keepClientNodes(root *yaml.Node) {
	if root == nil {
		return
	}
	if _, v := lookupKey(root, "client"); v != nil && !isNull(v) {
		c.clientNode = v
	}
	_, users := lookupKey(root, "users")
	if users == nil || users.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(users.Content); i += 2 {
		if _, v := lookupKey(users.Content[i+1], "client"); v != nil && !isNull(v) {
			if c.userClients == nil {
				c.userClients = map[string]*yaml.Node{}
			}
			c.userClients[users.Content[i].Value] = v
		}
	}
}

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
	Princo       string          `yaml:"princo"`
	Defaults     Defaults        `yaml:"defaults"`
	Nodes        Ordered[Node]   `yaml:"nodes"`
	Users        Ordered[User]   `yaml:"users"`
	Client       Client          `yaml:"client"`
	Subscription *Subscription   `yaml:"subscription"`
	Secrets      Ordered[string] `yaml:"secrets"`
}

// SecretMappings returns the secrets: block in document order.
func (c *Config) SecretMappings() []secrets.Mapping {
	var out []secrets.Mapping
	for pattern, target := range c.Secrets.All() {
		out = append(out, secrets.Mapping{Pattern: pattern, Target: target})
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
}

type Reality struct {
	ServerName string                 `yaml:"server_name"`
	ShortID    string                 `yaml:"short_id"`
	PublicKey  string                 `yaml:"public_key"`
	PrivateKey *secrets.SecretOrPlain `yaml:"private_key"`
}

type Hysteria2 struct {
	Masquerade   string                 `yaml:"masquerade"`
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
}

// Client describes the sing-box profile served to users.
type Client struct {
	Groups Ordered[Group] `yaml:"groups"`
	DNS    *DNS           `yaml:"dns"`
	Rules  []Rule         `yaml:"rules"`
	Final  string         `yaml:"final"`
}

// Group is a selector in the client app over some of the user's nodes.
type Group struct {
	// Nodes selects members by tag: "<tag>", "!<tag>" or "all".
	Nodes         string `yaml:"nodes"`
	Default       string `yaml:"default"`
	IncludeDirect bool   `yaml:"include_direct"`
	Fallback      string `yaml:"fallback"`
}

type Subscription struct {
	Node   string `yaml:"node"`
	Domain string `yaml:"domain"`
}

// Parse decodes a princo.yaml document strictly: unknown fields anywhere
// are errors, and the schema version must be v1.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse princo.yaml: %w", err)
	}
	switch cfg.Princo {
	case "v1":
		return &cfg, nil
	case "":
		return nil, fmt.Errorf("princo: required (set `princo: v1` at the top of the file)")
	default:
		return nil, fmt.Errorf("unsupported schema version %q (expected v1)", cfg.Princo)
	}
}

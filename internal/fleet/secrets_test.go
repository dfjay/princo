package fleet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/config"
)

func TestSecrets(t *testing.T) {
	// b's reality has no public_key yet: Build would refuse this config.
	cfg, err := config.Parse([]byte(`princo: v1
defaults:
  reality: { server_name: www.example.com, short_id: 01 }
nodes:
  b: { address: b.example.com, reality: {}, hysteria2: { obfs: salamander }, egress: a }
  a: { address: a.example.com, reality: { public_key: p }, hysteria2: { obfs: salamander }, egress: warp, warp: { ipv6: "::2" } }
users:
  u: {}
  v: { uuid: !secret keys/v }
  w: { uuid: plain-uuid }
`))
	require.NoError(t, err)
	require.Equal(t, []SecretUse{
		{"nodes/a/reality", "nodes.a.reality.private_key", SecretRealityKey},
		{"shared/hysteria2_obfs", "nodes.a.hysteria2.obfs_password", SecretPassword},
		{"nodes/b/reality", "nodes.b.reality.private_key", SecretRealityKey},
		{"shared/hysteria2_obfs", "nodes.b.hysteria2.obfs_password", SecretPassword},
		{"nodes/a/warp/private_key", "nodes.a.warp.private_key", SecretExternal},
		{"nodes/a/warp/ipv4", "nodes.a.warp.ipv4", SecretExternal},
		{"nodes/b/chain", "nodes.b.egress", SecretUUID},
		{"users/u", "users.u.uuid", SecretUUID},
		{"keys/v", "users.v.uuid", SecretUUID},
	}, Secrets(cfg))
}

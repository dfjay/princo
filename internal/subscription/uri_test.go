package subscription

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/fleet/fleettest"
)

func TestURIs(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	bob, _ := f.User("bob")
	require.Equal(t, []string{
		"vless://5ad0af17-e352-4d1e-a22a-a5d4007007da@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.samsung.com&fp=chrome&pbk=P-R8AofeIpznJ9PWf-FMZm17TspZbFspvXU2zDTRXhk&sid=2b4398e0#us-reality",
		"vless://5ad0af17-e352-4d1e-a22a-a5d4007007da@relay.example.ru:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.ozon.ru&fp=chrome&pbk=TueZqbh5xK2pH6ajdlAB8E-weA_Z8SUOL_PekPXsrBw&sid=f0447be7#relay-reality",
	}, URIs(bob))

	alice, _ := f.User("alice")
	uris := URIs(alice)
	require.Len(t, uris, 6, "de: reality, hysteria2, naive; us: reality; fi: reality, xhttp")
	require.Equal(t, "hysteria2://dbc5aca6-f0dd-416d-b30f-813754d72f99@de.example.com:443/?sni=de.example.com#de-hysteria2", uris[1])
	require.Equal(t, "naive+https://alice:dbc5aca6-f0dd-416d-b30f-813754d72f99@naive-de.example.com:443#de-naive", uris[2])
	require.Equal(t, "vless://dbc5aca6-f0dd-416d-b30f-813754d72f99@fi.example.com:443?encryption=none&type=xhttp&path=%2Ff7Kq2m&mode=auto&security=reality&sni=www.samsung.com&fp=chrome&pbk=x1UdIXGj0boXzk96E0ZBwNxdTvF-YwsK4XGVqVhvfFc&sid=3c5409f1#fi-reality-xhttp", uris[5])
}

func TestURIs_GRPC(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	bob, _ := f.User("bob")
	u := *bob
	us := *bob.Nodes[0]
	r := *us.Reality
	r.Transports = []fleet.Transport{{Kind: fleet.TransportGRPC, ServiceName: "a1b2c3"}}
	us.Reality = &r
	u.Nodes = []*fleet.Node{&us}
	require.Equal(t, []string{
		"vless://5ad0af17-e352-4d1e-a22a-a5d4007007da@203.0.113.7:443?encryption=none&type=grpc&serviceName=a1b2c3&mode=gun&security=reality&sni=www.samsung.com&fp=chrome&pbk=P-R8AofeIpznJ9PWf-FMZm17TspZbFspvXU2zDTRXhk&sid=2b4398e0#us-reality-grpc",
	}, URIs(&u), "no Vision flow over gRPC")
}

// Every transport there is has its link.
func TestURIs_EveryTransport(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	bob, _ := f.User("bob")
	u := *bob
	us := *bob.Nodes[0]
	r := *us.Reality
	r.Transports = nil
	for _, kind := range fleet.TransportKinds {
		r.Transports = append(r.Transports, fleet.Transport{Kind: kind, ServiceName: "s", Path: "/p", Mode: "auto"})
	}
	us.Reality = &r
	u.Nodes = []*fleet.Node{&us}
	uris := URIs(&u)
	require.Len(t, uris, len(fleet.TransportKinds))
	for i, kind := range fleet.TransportKinds {
		require.Contains(t, uris[i], "type="+kind+"&")
	}
}

func TestURIs_Hysteria2Obfs(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	alice, _ := f.User("alice")
	u := *alice
	de := *alice.Nodes[0]
	de.Hysteria2 = &fleet.Hysteria2{Obfs: "salamander", ObfsPassword: "p&q"}
	u.Nodes = []*fleet.Node{&de}
	require.Equal(t, "hysteria2://dbc5aca6-f0dd-416d-b30f-813754d72f99@de.example.com:443/?sni=de.example.com&obfs=salamander&obfs-password=p%26q#de-hysteria2", URIs(&u)[1])
}

func TestURIs_EscapesName(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	alice, _ := f.User("alice")
	u := *alice
	u.Name = "ops#team"
	// Nothing but unreserved characters stays: apps differ on the rest.
	u.Client = &fleet.Client{Label: "{user} {node}/{protocol} +&%·"}
	uris := URIs(&u)
	require.Equal(t, "naive+https://ops%23team:dbc5aca6-f0dd-416d-b30f-813754d72f99@naive-de.example.com:443#ops%23team%20de%2Fnaive%20%2B%26%25%C2%B7", uris[2])
	for _, uri := range uris {
		parsed, err := url.Parse(uri)
		require.NoError(t, err)
		require.Contains(t, parsed.Fragment, "ops#team ")
		require.Contains(t, parsed.Fragment, " +&%·")
	}

	links := UserLinks(f.Subscription.Domain(), &u)
	require.Equal(t, "sing-box://import-remote-profile?url=https%3A%2F%2Fsubs.example.com%2Ff8cb68efcef124689abd331ff3fa5241%2Fsing-box#ops%23team", links.SingBox)
}

func TestURIs_IPv6(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	alice, _ := f.User("alice")
	u := *alice
	fi := *alice.Nodes[2]
	fi.Address = "2001:db8::1"
	u.Nodes = []*fleet.Node{&fi}
	for _, uri := range URIs(&u) {
		parsed, err := url.Parse(uri)
		require.NoError(t, err)
		require.Equal(t, "2001:db8::1", parsed.Hostname(), uri)
		require.Equal(t, "443", parsed.Port(), uri)
	}
}

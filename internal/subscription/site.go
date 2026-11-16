package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/url"
	"path"
	"strings"

	"rsc.io/qr"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

// Token is the user's secret path segment on the subscription site. It
// comes from the UUID, so links stay the same across renders.
func Token(u *fleet.User) string {
	sum := sha256.Sum256([]byte(u.UUID))
	return hex.EncodeToString(sum[:])[:32]
}

// Links are a user's links to the subscription site.
type Links struct {
	// Universal is the subscription: share links for most apps, the
	// profile for sing-box apps.
	Universal string
	// SingBox imports the profile into sing-box apps.
	SingBox string
	// QR is the page with both as QR codes.
	QR string
}

// Profile is the URL of the profile in format, an engine's name, for
// platform p.
func (l Links) Profile(format string, p engine.Platform) string {
	return l.Universal + path.Join(format, string(p))
}

// UserLinks returns the user's links to the site at domain.
func UserLinks(domain string, u *fleet.User) Links {
	l := Links{Universal: "https://" + domain + "/" + Token(u) + "/"}
	l.QR = l.Universal + "qr"
	// https://sing-box.sagernet.org/clients/general/#remote-profile
	l.SingBox = "sing-box://import-remote-profile?url=" + url.QueryEscape(l.Profile("sing-box", engine.AnyPlatform)) +
		"#" + (&url.URL{Fragment: u.Name}).EscapedFragment()
	return l
}

// Site renders the subscription site as files relative to its root, for
// every domain and every user of the fleet. Each domain's files name it:
//
//	<domain>/<token>/base64                     share links, one per line, base64-encoded
//	<domain>/<token>/sing-box/config            the sing-box profile for the apps
//	<domain>/<token>/sing-box/<platform>/config the profile for each of client's platforms
//	<domain>/<token>/index.html                 both subscription links with QR codes
//	<domain>/<token>/qr-*.svg                   the QR codes
//
// The web server maps https://<domain>/<token>/ to base64 (or to the
// profile for sing-box apps), /<token>/base64 to base64 and
// /<token>/sing-box[/<platform>] to the profile.
func Site(f *fleet.Fleet, client engine.Engine) (map[string][]byte, error) {
	if f.Subscription == nil {
		return nil, fmt.Errorf("the fleet has no subscription")
	}
	files := map[string][]byte{}
	for _, domain := range f.Subscription.Domains {
		for _, u := range f.Users {
			if err := userFiles(files, f, client, domain, u); err != nil {
				return nil, err
			}
		}
	}
	return files, nil
}

// userFiles adds u's files of the site at domain to files.
func userFiles(files map[string][]byte, f *fleet.Fleet, client engine.Engine, domain string, u *fleet.User) error {
	dir := path.Join(domain, Token(u))
	for _, p := range append([]engine.Platform{engine.AnyPlatform}, client.ClientPlatforms()...) {
		profile, err := client.RenderClient(f, u.Name, p, domain)
		if err != nil {
			return fmt.Errorf("profile of %s: %w", u.Name, err)
		}
		files[path.Join(dir, client.Name(), string(p), "config")] = profile
	}
	links := UserLinks(domain, u)
	subQR, err := qrSVG(links.Universal)
	if err != nil {
		return err
	}
	singBoxQR, err := qrSVG(links.SingBox)
	if err != nil {
		return err
	}
	var page bytes.Buffer
	if err := pageTemplate.Execute(&page, map[string]any{
		"User":      u.Name,
		"Universal": links.Universal,
		// html/template blanks hrefs with schemes it doesn't know.
		"SingBox": template.URL(links.SingBox),
	}); err != nil {
		return err
	}
	uris := strings.Join(URIs(u), "\n")
	files[dir+"/base64"] = []byte(base64.StdEncoding.EncodeToString([]byte(uris)))
	files[dir+"/index.html"] = page.Bytes()
	files[dir+"/qr-sub.svg"] = subQR
	files[dir+"/qr-singbox.svg"] = singBoxQR
	return nil
}

// qrSVG draws text as a QR code with the standard 4-module quiet zone.
func qrSVG(text string) ([]byte, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, fmt.Errorf("qr code: %w", err)
	}
	const quiet = 4
	size := code.Size + 2*quiet
	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, size, size)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, size, size)
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.Bytes(), nil
}

var pageTemplate = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.User}}</title>
<style>body{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#111;color:#fff;font-family:system-ui;padding:2em 0}.qr{text-align:center;margin:1.5em 0}img{width:min(500px,90vw)}a{color:#7af;font-size:0.85em;word-break:break-all}h3{margin:0.5em 0;font-weight:400;opacity:0.7}</style>
</head><body>
<h2>{{.User}}</h2>
<div class="qr"><h3>Universal</h3><img src="qr-sub.svg" alt="QR"><br><a href="{{.Universal}}">{{.Universal}}</a></div>
<div class="qr"><h3>sing-box 1.14+</h3><img src="qr-singbox.svg" alt="QR"><br><a href="{{.SingBox}}">{{.SingBox}}</a></div>
</body></html>
`))

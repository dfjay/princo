package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"rsc.io/qr"

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

// UserLinks returns the user's links, or false when the fleet has no
// subscription.
func UserLinks(f *fleet.Fleet, u *fleet.User) (Links, bool) {
	if f.Subscription == nil {
		return Links{}, false
	}
	universal := "https://" + f.Subscription.Domain + "/" + Token(u) + "/"
	return Links{
		Universal: universal,
		// https://sing-box.sagernet.org/clients/general/#remote-profile
		SingBox: "sing-box://import-remote-profile?url=" + url.QueryEscape(universal+"sing-box") +
			"#" + (&url.URL{Fragment: u.Name}).EscapedFragment(),
		QR: universal + "qr",
	}, true
}

// Site renders the subscription site as files relative to its root, for
// every user of the fleet:
//
//	<token>/base64          share links, one per line, base64-encoded
//	<token>/sing-box/config the sing-box profile
//	<token>/index.html      both subscription links with QR codes
//	<token>/qr-*.svg        the QR codes
//
// The web server maps https://<domain>/<token>/ to base64 (or to the
// profile for sing-box apps) and /<token>/sing-box to the profile, which
// Site gets from profile.
func Site(f *fleet.Fleet, profile func(user string) ([]byte, error)) (map[string][]byte, error) {
	if f.Subscription == nil {
		return nil, fmt.Errorf("the fleet has no subscription")
	}
	files := map[string][]byte{}
	for _, u := range f.Users {
		token := Token(u)
		p, err := profile(u.Name)
		if err != nil {
			return nil, fmt.Errorf("profile of %s: %w", u.Name, err)
		}
		links, _ := UserLinks(f, u)
		subQR, err := qrSVG(links.Universal)
		if err != nil {
			return nil, err
		}
		singBoxQR, err := qrSVG(links.SingBox)
		if err != nil {
			return nil, err
		}
		var page bytes.Buffer
		if err := pageTemplate.Execute(&page, map[string]any{
			"User":      u.Name,
			"Universal": links.Universal,
			// html/template blanks hrefs with schemes it doesn't know.
			"SingBox": template.URL(links.SingBox),
		}); err != nil {
			return nil, err
		}

		uris := strings.Join(URIs(u), "\n")
		files[token+"/base64"] = []byte(base64.StdEncoding.EncodeToString([]byte(uris)))
		files[token+"/sing-box/config"] = p
		files[token+"/index.html"] = page.Bytes()
		files[token+"/qr-sub.svg"] = subQR
		files[token+"/qr-singbox.svg"] = singBoxQR
	}
	return files, nil
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

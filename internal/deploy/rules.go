package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/ruledata"
)

// RuleSets builds the rule sets named from the fleet's rule data, read from
// dir, or the latest downloaded when dir is empty. config is the node's
// server config.
func RuleSets(ctx context.Context, client *http.Client, dir string, src fleet.RuleData, names []string, config []byte) (map[string][]byte, error) {
	var geoip, geosite []byte
	var err error
	if dir != "" {
		if geoip, geosite, err = ruledata.ReadDir(dir); err != nil {
			return nil, err
		}
	} else {
		needGeoIP, needGeosite := ruledata.Needs(names)
		https := httpsOnly(client)
		get := func(ctx context.Context, url string) ([]byte, error) { return Fetch(ctx, https, url) }
		if needGeoIP {
			if geoip, err = ruledata.Fetch(ctx, get, src.GeoIP, time.Now()); err != nil {
				return nil, fmt.Errorf("geoip data: %w", err)
			}
		}
		if needGeosite {
			if geosite, err = ruledata.Fetch(ctx, get, src.Geosite, time.Now()); err != nil {
				return nil, fmt.Errorf("geosite data: %w", err)
			}
		}
	}
	data, err := ruledata.New(geoip, geosite)
	if err != nil {
		return nil, err
	}
	return data.Files(names, config)
}

// httpsOnly is client refusing a redirect that leaves HTTPS.
func httpsOnly(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirected to %s, which isn't https", req.URL)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &c
}

// Published checks that url, where the client profiles fetch them, serves
// every rule set named: an app doesn't start without one. It compares no
// contents, as newer rule data builds other files.
func Published(ctx context.Context, client *http.Client, url string, names []string) error {
	client = httpsOnly(client)
	var missing []string
	for _, name := range names {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url+name, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("rule set %s: %w", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			missing = append(missing, fmt.Sprintf("%s (%s)", name, resp.Status))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s doesn't serve %s; publish what princo rule-sets --client builds there first", url, strings.Join(missing, ", "))
	}
	return nil
}

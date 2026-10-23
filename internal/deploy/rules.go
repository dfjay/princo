package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
		httpsOnly := *client
		httpsOnly.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirected to %s, which isn't https", req.URL)
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		}
		get := func(ctx context.Context, url string) ([]byte, error) { return Fetch(ctx, &httpsOnly, url) }
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

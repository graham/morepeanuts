package suez

import (
	"net/http"
	"strings"
)

type GatekeeperResponse int

const (
	GATEKEEPER_ALLOW        GatekeeperResponse = iota // User is allowed.
	GATEKEEPER_DENY         GatekeeperResponse = iota // User is not allowed.
	GATEKEEPER_AUTH         GatekeeperResponse = iota // User requires authentication.
	GATEKEEPER_BACKPRESSURE GatekeeperResponse = iota // backpressure to client. (not supported)
	GATEKEEPER_LIMIT        GatekeeperResponse = iota // Api Limit.              (not supported)
)

type Gatekeeper interface {
	IsAllowed(hci *HostConfigItem, identity string, r *http.Request) GatekeeperResponse
	BackpressureTime(identity string, r *http.Request) int
}

type DefaultGatekeeper struct{}

func (g DefaultGatekeeper) IsAllowed(hci *HostConfigItem, identity string, r *http.Request) GatekeeperResponse {
	var fulluri string = r.RequestURI

	//defer timeTrack(time.Now(), fmt.Sprintf("DefaultGatekeeper.IsAllowed - %s - ", fulluri))

	if len(identity) == 0 {
		if hci.Authorization.RequireAuth == true {
			var IsPassthrough bool = HasPrefixFromList(
				fulluri,
				hci.Authorization.PassthroughRoutes,
			)
			if IsPassthrough == false {
				return GATEKEEPER_AUTH
			}
		} else {
			var IsGuarded bool = HasPrefixFromList(
				fulluri,
				hci.Authorization.GuardedRoutes,
			)
			if IsGuarded == true {
				return GATEKEEPER_AUTH
			}
		}
	} else {
		if hci.Authorization.AllowAll == false {
			var hit bool = false
			for _, testEmail := range hci.Authorization.AllowList {
				if testEmail[0] == '@' && strings.HasSuffix(identity, testEmail) {
					hit = true
				} else if identity == testEmail {
					hit = true
				}
			}

			if hit == false {
				return GATEKEEPER_DENY
			}
		}
	}
	return GATEKEEPER_ALLOW
}

func (g DefaultGatekeeper) BackpressureTime(identity string, r *http.Request) int {
	return 250
}

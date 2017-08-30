package suez

import "strings"

type GatekeeperResponse int

const (
	GATEKEEPER_ALLOW        GatekeeperResponse = iota // User is allowed.
	GATEKEEPER_DENY         GatekeeperResponse = iota // User is not allowed.
	GATEKEEPER_AUTH         GatekeeperResponse = iota // User requires authentication.
	GATEKEEPER_BACKPRESSURE GatekeeperResponse = iota // backpressure to client. (not supported)
	GATEKEEPER_LIMIT        GatekeeperResponse = iota // Api Limit.              (not supported)
)

type Gatekeeper interface {
	IsAllowed(hci *HostConfigItem, identity, fulluri string) GatekeeperResponse
}

type DefaultGatekeeper struct{}

func (g DefaultGatekeeper) IsAllowed(hci *HostConfigItem, identity, fulluri string) GatekeeperResponse {
	if len(identity) == 0 {
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
	} else {
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
	}
	return GATEKEEPER_ALLOW
}

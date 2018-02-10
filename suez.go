package suez

import (
	"golang.org/x/oauth2"
)

// Host Config Item

type HostAuthentication struct {
	// Name of the cookie that holds user Authentication.
	CookieName string `toml:"cookie_name"`

	// How long that cookie lasts.
	CookieDurationDays int `toml:"cookie_duration_days"`

	// Oauth2 Client Id
	ClientID string `toml:"client_id"`

	// Oauth2 Client Secret
	ClientSecret string `toml:"client_secret"`

	// Scopes requested on authentication.
	InitScopes []string `toml:"init_scopes"`

	// Method for getting user information (email)
	UserInfoUrl string `toml:"user_info_url"`

	// Should the UserInfoUrl be a post request?
	UserInfoPost bool `toml:"user_info_method_post"`

	// custom endpoints as array of strings.
	EndpointStr []string `toml:"endpoint"`

	// Sane defaults will compile the array above into a
	// go struct.}
	Endpoint oauth2.Endpoint
}

type HostAuthorization struct {
	// Name of cookie that holds oauth2 token.
	CookieName string `toml:"cookie_name"`

	// Should all routes require auth?
	RequireAuth bool `toml:"require_auth"`

	// If require auth == true, allow some passthrough routes.
	PassthroughRoutes []string `toml:"passthrough_routes"`

	// If require auth == false, allow some routes to be guarded.
	GuardedRoutes []string `toml:"guarded_routes"`

	// Once a user is authenticated, should you allow all users?
	AllowAll bool `toml:"allow_all"`

	// If not, what is the list of users that you want to allow.
	AllowList []string `toml:"allow_list"`

	// User defined data to be passed to the gatekeeper.
	GatekeeperArgs interface{} `toml:"gatekeeper_args"`

	// Gatekeeper interface, can be user defined.
	Gatekeeper Gatekeeper
}

// End Host Config Item

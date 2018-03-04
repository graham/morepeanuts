package suez

import (
	"log"
	"net/http"
	"regexp"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type HostConfigItem struct {
	Domain                string             `toml:"domain"`
	Dial                  string             `toml:"dial"`
	InnerProtocol         string             `toml:"inner_protocol"`
	OuterProtocol         string             `toml:"outer_protocol"`
	CookiePassthrough     bool               `toml:"cookie_passthrough"`
	CookieEncryptionKey   string             `toml:"cookie_encryption_key"`
	RouteMount            string             `toml:"route_mount"`
	AlwaysUseCustomDialer bool               `toml:"always_use_custom_dialer"`
	Authentication        HostAuthentication `toml:"authentication"`
	Authorization         HostAuthorization  `toml:"authorization"`

	Static struct {
		DirectoryMappings [][]string `toml:"directory_mappings"`
		StaticOnly        bool       `toml:"static_only"`
	}

	Router       http.Handler
	CustomDialer Dialer
	Logger       Logger
	RegexMatcher *regexp.Regexp
}

func (hci *HostConfigItem) SaneDefaults() {
	if hci.Static.StaticOnly {
		if len(hci.Static.DirectoryMappings) == 0 {
			hci.Static.DirectoryMappings = [][]string{[]string{"/", "./"}}
		}
		return
	}

	if len(hci.Domain) == 0 {
		hci.Domain = "127.0.0.1"
	}

	if len(hci.Dial) == 0 {
		hci.Dial = "127.0.0.1"
	}

	if hci.InnerProtocol == "" {
		hci.InnerProtocol = "http"
	}

	if hci.OuterProtocol == "" {
		hci.OuterProtocol = "https"
	}

	if hci.Authorization.CookieName == "" {
		hci.Authorization.CookieName = "suez_identity_key"
	}

	if hci.Authentication.CookieName == "" {
		hci.Authentication.CookieName = "suez_authentication_key"
	}

	if hci.Authentication.CookieDurationDays == 0 {
		hci.Authentication.CookieDurationDays = 1
	}

	if len(hci.Authentication.InitScopes) == 0 {
		log.Println("No init scopes set, using default: [https://www.googleapis.com/auth/userinfo.email]")
		hci.Authentication.InitScopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
	}

	if len(hci.Authentication.EndpointStr) == 0 {
		log.Printf("No explicit endpoints set, going with default: %s\n", google.Endpoint)
		hci.Authentication.Endpoint = google.Endpoint
	} else {
		hci.Authentication.Endpoint = oauth2.Endpoint{
			AuthURL:  hci.Authentication.EndpointStr[0],
			TokenURL: hci.Authentication.EndpointStr[1],
		}
	}

	if len(hci.Authentication.UserInfoUrl) == 0 {
		log.Printf("Using default user info path https://www.googleapis.com/oauth2/v3/userinfo")
		hci.Authentication.UserInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo"
		hci.Authentication.UserInfoPost = false
	}

	if hci.RouteMount == "" {
		hci.RouteMount = "_/"
	}

	hci.Authorization.Gatekeeper = DefaultGatekeeper{}
	hci.CustomDialer = DefaultDialer{}
	hci.Logger = NewDefaultLogger()
}

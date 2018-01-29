package suez

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/julienschmidt/httprouter"
)

// Reverse Proxy
var netTransport = &http.Transport{
	Dial: (&net.Dialer{
		Timeout: 5 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 5 * time.Second,
}

var netClient = &http.Client{
	Timeout:   time.Second * 10,
	Transport: netTransport,
}

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

type HostConfigItem struct {
	Domain                string             `toml:"domain"`
	Dial                  string             `toml:"dial"`
	InnerProtocol         string             `toml:"protocol"`
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

	Router        http.Handler
	CustomDialer  Dialer
	OuterProtocol string
	Logger        Logger
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

	if hci.Dial == "" {
		panic("Must specify a 'dial' target under [host]")
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

	if hci.Authentication.ClientID == "" {
		panic("[host.authentication] must contain a client_id")
	}

	if hci.Authentication.ClientSecret == "" {
		panic("[host.authentication] must contain a client_secret")
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

func BuildRouter(hci HostConfigItem, FQDN string) *httprouter.Router {
	hci.SaneDefaults()
	router := httprouter.New()

	if len(hci.Static.DirectoryMappings) > 0 {
		for _, pair := range hci.Static.DirectoryMappings {
			publicPath := fmt.Sprintf("%s*filepath", pair[0])
			fileSystemPath := pair[1]
			router.ServeFiles(publicPath, http.Dir(fileSystemPath))
		}

		if hci.Static.StaticOnly {
			return router
		}
	}

	identUrl := hci.Authentication.UserInfoUrl
	identPost := hci.Authentication.UserInfoPost

	target, _ := url.Parse(fmt.Sprintf("%s://%s", hci.InnerProtocol, hci.Dial))

	router.NotFound = ReverseProxy{
		Proxy:    httputil.NewSingleHostReverseProxy(target),
		HostItem: &hci,
	}

	OauthConfig := &oauth2.Config{
		ClientID:     hci.Authentication.ClientID,
		ClientSecret: hci.Authentication.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/%sauth", FQDN, hci.RouteMount),
		Scopes:       hci.Authentication.InitScopes,
		Endpoint:     hci.Authentication.Endpoint,
	}

	router.GET(fmt.Sprintf("/%slogin", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			queryValues := r.URL.Query()
			next := queryValues.Get("next")

			if len(next) > 0 {
				http.SetCookie(w, MakeCookie("next", next, 1))
			} else {
				http.SetCookie(w, MakeCookie("next", "", -101))
			}

			randomToken := GenRandomString()

			http.SetCookie(w,
				MakeCookie(
					hci.Authentication.CookieName,
					randomToken,
					hci.Authentication.CookieDurationDays,
				),
			)

			options := OptionsFromQuery(hci, queryValues)
			if len(FQDN) == 0 {
				OauthConfig.RedirectURL = fmt.Sprintf("%s://%s/%sauth", hci.OuterProtocol, r.Host, hci.RouteMount)
			}
			url := OauthConfig.AuthCodeURL(randomToken, options...)
			fmt.Fprintln(w, HtmlRedirect(url))
		})

	router.GET(fmt.Sprintf("/%slogout", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			queryValues := r.URL.Query()
			next := queryValues.Get("next")

			http.SetCookie(w, MakeCookie(hci.Authentication.CookieName, "", -101))
			http.SetCookie(w, MakeCookie(hci.Authorization.CookieName, "", -101))

			if len(next) == 0 {
				fmt.Fprintf(w, "<html><body>You have been logged out.</body></html>")
			} else {
				fmt.Fprintf(w, HtmlRedirect(next))
				http.SetCookie(w, MakeCookie("next", "/", -100))
			}
		})

	router.GET(fmt.Sprintf("/%sauth", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			cookie, err := r.Cookie(hci.Authentication.CookieName)

			if err != nil {
				log.Printf("Cookie Error: %s\n", err)
				http.SetCookie(w, MakeCookie(hci.Authentication.CookieName, "", -101))
				http.SetCookie(w, MakeCookie(hci.Authorization.CookieName, "", -101))
				fmt.Fprintln(w, HtmlRedirect(fmt.Sprintf("/%slogin", hci.RouteMount)))
				return
			}

			queryValues := r.URL.Query()
			urlState := queryValues.Get("state")

			if urlState != cookie.Value {
				log.Printf("values didnt match: %s %s\n", urlState, cookie.Value)
				http.SetCookie(w, MakeCookie(hci.Authentication.CookieName, "", -101))
				http.SetCookie(w, MakeCookie(hci.Authorization.CookieName, "", -101))
				fmt.Fprintf(w, "<html><body>An error occurred.</body></html>")
				return
			}

			code := queryValues.Get("code")
			tok, terr := OauthConfig.Exchange(oauth2.NoContext, code)

			if terr != nil {
				panic(terr)
			}

			b, _ := json.Marshal(tok)

			enc_value, _ := Encrypt(hci.CookieEncryptionKey, string(b))
			http.SetCookie(w, MakeCookie(
				hci.Authentication.CookieName,
				enc_value,
				hci.Authentication.CookieDurationDays,
			))

			client := OauthConfig.Client(oauth2.NoContext, tok)
			email, email_err := GetIdentityWithClient(identUrl, identPost, client)

			if email_err != nil {
				http.SetCookie(w, MakeCookie(hci.Authentication.CookieName, "", -101))
				http.SetCookie(w, MakeCookie(hci.Authorization.CookieName, "", -101))
				fmt.Fprintf(w, "<html><body>Invalid Token %s</Body></html>", email_err)
				return
			}

			ident_enc_value, _ := Encrypt(
				hci.CookieEncryptionKey,
				email,
			)
			http.SetCookie(w, MakeCookie(
				hci.Authorization.CookieName,
				ident_enc_value,
				hci.Authentication.CookieDurationDays,
			))

			cookie, err = r.Cookie("next")
			if err != nil {
				fmt.Fprintf(w, HtmlRedirect(fmt.Sprintf("/%stest", hci.RouteMount)))
				http.SetCookie(w, MakeCookie("next", "", -100))
			} else {
				url := cookie.Value
				fmt.Fprintf(w, HtmlRedirect(url))
				http.SetCookie(w, MakeCookie("next", "", -100))
			}
		})

	router.GET(fmt.Sprintf("/%stest", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			encrypted_ident_string, _ := r.Cookie(hci.Authorization.CookieName)
			ident_string, _ := Decrypt(hci.CookieEncryptionKey, encrypted_ident_string.Value)

			cookie, err := r.Cookie(hci.Authentication.CookieName)
			var tok oauth2.Token

			if err != nil {
				fmt.Fprintf(w, "<html><body>Not logged in</body></html>")
				return
			}

			decrypted_code, _ := Decrypt(hci.CookieEncryptionKey, cookie.Value)

			json.Unmarshal([]byte(decrypted_code), &tok)

			client := OauthConfig.Client(oauth2.NoContext, &tok)
			email, email_err := GetIdentityWithClient(identUrl, identPost, client)

			if email_err != nil {
				log.Println(email_err)
				fmt.Fprintf(w, "<html><body>Invalid Token</Body></html>")
				return
			}

			fmt.Fprintf(w, "<html><body>")
			fmt.Fprintf(w, "<div>IdentityKey   : %s</div>", ident_string)
			fmt.Fprintf(w, "<div>ClientIdentity: %s</div>", email)
			fmt.Fprintf(w, "</body></html>")
		})

	router.GET(fmt.Sprintf("/%slanding", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			fmt.Fprintf(w, "<html><body><a href='/%slogin'>Login</a></body></html>", hci.RouteMount)
		})

	router.GET(fmt.Sprintf("/%sadd_scopes", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			queryValues := r.URL.Query()

			scopes := strings.Split(queryValues.Get("scopes"), ",")
			scopes = append(scopes, hci.Authentication.InitScopes...)

			TempOauthConfig := &oauth2.Config{
				ClientID:     hci.Authentication.ClientID,
				ClientSecret: hci.Authentication.ClientSecret,
				RedirectURL:  fmt.Sprintf("%s/%sauth", FQDN, hci.RouteMount),
				Scopes:       scopes,
				Endpoint:     hci.Authentication.Endpoint,
			}

			randomToken := GenRandomString()
			http.SetCookie(w, MakeCookie(
				hci.Authentication.CookieName,
				randomToken,
				hci.Authentication.CookieDurationDays,
			))

			next := queryValues.Get("next")
			if len(next) > 0 {
				http.SetCookie(w, MakeCookie("next", next, 1))
			} else {
				http.SetCookie(w, MakeCookie("next", "", -101))
			}

			options := OptionsFromQuery(hci, queryValues)
			if len(FQDN) == 0 {
				TempOauthConfig.RedirectURL = fmt.Sprintf("%s://%s/%sauth", hci.OuterProtocol, r.Host, hci.RouteMount)
			}

			fmt.Fprintln(w, HtmlRedirect(TempOauthConfig.AuthCodeURL(randomToken, options...)))
		})

	router.GET(fmt.Sprintf("/%shello/:name", hci.RouteMount),
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
		})

	return router
}

// End Host Config Item

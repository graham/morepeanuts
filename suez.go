package suez

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/handlers"
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

// Server Config Item

type ServerConfigItem struct {
	IsSecure             bool       `toml:"secure"`
	Bind                 string     `toml:"bind"`
	Port                 int        `toml:"port"`
	SSLCertificates      [][]string `toml:"ssl_cert_pairs"`
	AutoRedirectInsecure bool       `toml:"auto_redirect_insecure"`
	DomainToHostMap      map[string]HostConfigItem
	NotFound             *HostConfigItem
}

func (sci *ServerConfigItem) SaneDefaults() {
	if sci.Bind == "" {
		sci.Bind = "127.0.0.1"
	}

	if sci.Port == 0 {
		if sci.IsSecure {
			sci.Port = 443
		} else {
			sci.Port = 80
		}
	}

	sci.DomainToHostMap = make(map[string]HostConfigItem)
}

func (sci ServerConfigItem) Listen() {
	if sci.IsSecure && sci.AutoRedirectInsecure == true {
		log.Printf("Staring insecure server on port 80 to redirect to %d\n", sci.Port)
		go http.ListenAndServe(
			fmt.Sprintf("%s:80", sci.Bind),
			http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var target string
				if sci.Port != 443 {
					target = fmt.Sprintf("https://%s:%d%s", req.Host, sci.Port, req.URL.RequestURI())
				} else {
					target = fmt.Sprintf("https://%s%s", req.Host, req.URL.RequestURI())
				}
				http.Redirect(w,
					req,
					target,
					http.StatusTemporaryRedirect,
				)
			}),
		)
	}

	if sci.IsSecure == true {
		cfg := &tls.Config{}

		for _, pair := range sci.SSLCertificates {
			cert, err := tls.LoadX509KeyPair(pair[0], pair[1])
			if err != nil {
				log.Fatal(err)
			}
			cfg.Certificates = append(cfg.Certificates, cert)
		}

		cfg.BuildNameToCertificate()

		server := http.Server{
			Addr:      fmt.Sprintf("%s:%d", sci.Bind, sci.Port),
			Handler:   handlers.LoggingHandler(os.Stdout, sci),
			TLSConfig: cfg,
		}

		server.ListenAndServeTLS("", "")
	} else {
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("%s:%d", sci.Bind, sci.Port),
			handlers.LoggingHandler(os.Stdout, sci)),
		)
	}
}

func (sci ServerConfigItem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var hostItem HostConfigItem
	var found bool

	if hostItem, found = sci.DomainToHostMap[r.Host]; found == false {
		if sci.NotFound == nil {
			fmt.Fprintf(w, "Wasn't able to find: %s", r.RequestURI)
			return
		} else {
			sci.NotFound.Router.ServeHTTP(w, r)
			return
		}
	}

	hostItem.Router.ServeHTTP(w, r)
}

// End Server Config Item

// Host Config Item

type HostConfigItem struct {
	Domain                string `toml:"domain"`
	Dial                  string `toml:"dial"`
	InnerProtocol         string `toml:"protocol"`
	OuterProtocol         string
	CookiePassthrough     bool   `toml:"cookie_passthrough"`
	CookieEncryptionKey   string `toml:"cookie_encryption_key"`
	AutoRedirectInsecure  bool   `toml:"auto_redirect_insecure"`
	RouteMount            string `toml:"route_mount"`
	AlwaysUseCustomDialer bool   `toml:"always_use_custom_dialer"`

	Authentication struct {
		CookieName         string     `toml:"cookie_name"`
		CookieDurationDays int        `toml:"cookie_duration_days"`
		ClientID           string     `toml:"client_id"`
		ClientSecret       string     `toml:"client_secret"`
		InitScopes         []string   `toml:"init_scopes"`
		AddValues          [][]string `toml:"add_values"`
		UserInfoUrl        string     `toml:"user_info_url"`
		UserInfoPost       bool       `toml:"user_info_method_post"`
		EndpointStr        []string   `toml:"endpoint"`
		Endpoint           oauth2.Endpoint
	} `toml:"authentication"`

	Authorization struct {
		RequireAuth       bool        `toml:"require_auth"`
		AllowAll          bool        `toml:"allow_all"`
		AllowList         []string    `toml:"allow_list"`
		CookieName        string      `toml:"cookie_name"`
		PassthroughRoutes []string    `toml:"passthrough_routes"`
		GuardedRoutes     []string    `toml:"guarded_routes"`
		GatekeeperArgs    interface{} `toml:"gatekeeper_args"`
		Gatekeeper        Gatekeeper
	} `toml:"authorization"`

	Static struct {
		DirectoryMappings [][]string `toml:"directory_mappings"`
		StaticOnly        bool       `toml:"static_only"`
	}

	OauthConfig  *oauth2.Config
	Router       http.Handler
	CustomDialer SuezDialerInterface
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
	if hci.CustomDialer == nil {
		hci.CustomDialer = SuezDialer{}
	}
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

	router.NotFound = SuezReverseProxy{
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

			fmt.Fprintf(w, "<html><body>%s</body></html>", email)
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
				OauthConfig.RedirectURL = fmt.Sprintf("%s://%s/%sauth", hci.OuterProtocol, r.Host, hci.RouteMount)
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

func LoadServerFromConfig(filename string) ServerConfigItem {
	b, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}

	var config struct {
		Server          ServerConfigItem `toml:"server"`
		HostConfigItems []HostConfigItem `toml:"host"`
	}

	_, err = toml.Decode(string(b), &config)

	if err != nil {
		panic(err)
	}

	var protocol string
	if config.Server.IsSecure {
		protocol = "https"
	} else {
		protocol = "http"
	}

	config.Server.SaneDefaults()

	for _, hci := range config.HostConfigItems {
		var fullDomain string

		if config.Server.Port == 80 || config.Server.Port == 443 {
			fullDomain = hci.Domain
		} else {
			fullDomain = fmt.Sprintf("%s:%d", hci.Domain, config.Server.Port)
		}

		if hci.Domain == "*" {
			config.Server.NotFound = &hci
			if config.Server.IsSecure == false {
				hci.OuterProtocol = "http"
			}
			config.Server.NotFound.Router = BuildRouter(hci, "")
		} else {
			FQDN := fmt.Sprintf("%s://%s", protocol, fullDomain)
			hci.Router = BuildRouter(hci, FQDN)
			config.Server.DomainToHostMap[fullDomain] = hci
		}
	}

	return config.Server
}

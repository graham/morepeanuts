package suez

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/gorilla/handlers"
	"github.com/julienschmidt/httprouter"
)

// Reverse Proxy

type SuezReverseProxy struct {
	Proxy    *httputil.ReverseProxy
	HostItem *HostConfigItem
}

func (mrp SuezReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(mrp.HostItem.Authorization.CookieName)

	if err != nil {
		if mrp.HostItem.Authorization.RequireAuth == true {
			fmt.Fprintf(w, HtmlRedirect("/_/login?next=%s"), r.RequestURI)
			return
		} else {
			r.Header.Set("X-Suez-Identity", "")
		}
	} else {
		email, _ := Decrypt(mrp.HostItem.CookieEncryptionKey, cookie.Value)
		if mrp.HostItem.Authorization.AllowAll {
			r.Header.Set("X-Suez-Auth", email)
		} else {
			var hit bool = false
			for _, testEmail := range mrp.HostItem.Authorization.AllowList {
				if email == testEmail {
					hit = true
				}
			}

			if hit == true {
				r.Header.Set("X-Suez-Auth", email)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("401 - Not authorized"))
				return
			}
		}
	}

	cookies := r.Cookies()
	remaining_cookies := make([]string, 0)

	for _, i := range cookies {
		if i.Name == mrp.HostItem.Authentication.CookieName ||
			i.Name == mrp.HostItem.Authorization.CookieName {
			if mrp.HostItem.CookiePassthrough == false {
				continue
			} else {
				newValue, _ := Decrypt(mrp.HostItem.CookieEncryptionKey, i.Value)
				i.Value = base64.URLEncoding.EncodeToString([]byte(newValue))
			}
		}
		remaining_cookies = append(
			remaining_cookies,
			MakeCookie(i.Name, i.Value, 1).String(),
		)
	}

	r.Header.Set("Cookie", strings.Join(remaining_cookies, ";"))
	mrp.Proxy.ServeHTTP(w, r)
}

// End Reverse Proxy

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
	Domain              string `toml:"domain"`
	Dial                string `toml:"dial"`
	CookiePassthrough   bool   `toml:"cookie_passthrough"`
	CookieEncryptionKey string `toml:"cookie_encryption_key"`

	AutoRedirectInsecure bool `toml:"auto_redirect_insecure"`

	FQDN string

	Authentication struct {
		CookieName         string `toml:"cookie_name"`
		CookieDurationDays int    `toml:"cookie_duration_days"`

		ClientID     string `toml:"client_id"`
		ClientSecret string `toml:"client_secret"`

		InitScopes []string `toml:"init_scopes"`

		AddValues    [][]string `toml:"add_values"`
		UserInfoUrl  string     `toml:"user_info_url"`
		UserInfoPost bool       `toml:"user_info_method_post"`

		EndpointStr []string `toml:"endpoint"`
		Endpoint    oauth2.Endpoint
	} `toml:"authentication"`

	Authorization struct {
		RequireAuth bool       `toml:"require_auth"`
		AllowAll    bool       `toml:"allow_all"`
		AllowList   []string   `toml:"allow_list"`
		AllowArgs   [][]string `toml:"allow_args"`
		CookieName  string     `toml:"cookie_name"`
	} `toml:"authorization"`

	Static struct {
		DirectoryMappings [][]string `toml:"directory_mappings"`
		StaticOnly        bool       `toml:"static_only"`
	}

	OauthConfig *oauth2.Config
	Router      http.Handler
	Proxy       *httputil.ReverseProxy
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
}

func BuildRouter(hci HostConfigItem, FQDN string) *httprouter.Router {
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

	target, _ := url.Parse(hci.Dial)
	router.NotFound = SuezReverseProxy{
		Proxy:    httputil.NewSingleHostReverseProxy(target),
		HostItem: &hci,
	}

	OauthConfig := &oauth2.Config{
		ClientID:     hci.Authentication.ClientID,
		ClientSecret: hci.Authentication.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/_/auth", FQDN),
		Scopes:       hci.Authentication.InitScopes,
		Endpoint:     hci.Authentication.Endpoint,
	}

	router.GET("/_/login", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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
			OauthConfig.RedirectURL = fmt.Sprintf("http://%s/_/auth", r.Host)
		}
		url := OauthConfig.AuthCodeURL(randomToken, options...)
		fmt.Fprintln(w, HtmlRedirect(url))
	})

	router.GET("/_/logout", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	router.GET("/_/auth", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		cookie, err := r.Cookie(hci.Authentication.CookieName)

		if err != nil {
			log.Printf("Cookie Error: %s\n", err)
			http.SetCookie(w, MakeCookie(hci.Authentication.CookieName, "", -101))
			http.SetCookie(w, MakeCookie(hci.Authorization.CookieName, "", -101))
			fmt.Fprintln(w, HtmlRedirect("/_/login"))
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
		email, email_err := getIdentityWithClient(identUrl, identPost, client)

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
			fmt.Fprintf(w, HtmlRedirect("/_/test"))
			http.SetCookie(w, MakeCookie("next", "", -100))
		} else {
			url := cookie.Value
			fmt.Fprintf(w, HtmlRedirect(url))
			http.SetCookie(w, MakeCookie("next", "", -100))
		}
	})

	router.GET("/_/test", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		cookie, err := r.Cookie(hci.Authentication.CookieName)
		var tok oauth2.Token

		if err != nil {
			fmt.Fprintf(w, "<html><body>Not logged in</body></html>")
			return
		}

		decrypted_code, _ := Decrypt(hci.CookieEncryptionKey, cookie.Value)

		json.Unmarshal([]byte(decrypted_code), &tok)

		client := OauthConfig.Client(oauth2.NoContext, &tok)
		email, email_err := getIdentityWithClient(identUrl, identPost, client)

		if email_err != nil {
			log.Println(email_err)
			fmt.Fprintf(w, "<html><body>Invalid Token</Body></html>")
			return
		}

		fmt.Fprintf(w, "<html><body>%s</body></html>", email)
	})

	router.GET("/_/landing", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "<html><body><a href='/_/login'>Login</a></body></html>")
	})

	router.GET("/_/add_scopes", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		queryValues := r.URL.Query()

		scopes := strings.Split(queryValues.Get("scopes"), ",")
		scopes = append(scopes, hci.Authentication.InitScopes...)

		TempOauthConfig := &oauth2.Config{
			ClientID:     hci.Authentication.ClientID,
			ClientSecret: hci.Authentication.ClientSecret,
			RedirectURL:  fmt.Sprintf("%s/_/auth", FQDN),
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
			OauthConfig.RedirectURL = fmt.Sprintf("http://%s/_/auth", r.Host)
		}
		fmt.Fprintln(w, HtmlRedirect(TempOauthConfig.AuthCodeURL(randomToken, options...)))
	})

	router.GET("/_/hello/:name", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
	})

	return router
}

// End Host Config Item

// Util

func Encrypt(key string, text string) (string, error) {
	if len(key) == 0 {
		return text, nil
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	b := base64.URLEncoding.EncodeToString([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	bc := base64.URLEncoding.EncodeToString(ciphertext)
	return bc, nil
}

func Decrypt(key, b64text string) (string, error) {
	text, _ := base64.URLEncoding.DecodeString(b64text)
	if len(key) == 0 {
		return string(text), nil
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	if len(text) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.URLEncoding.DecodeString(string(text))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func MakeCookie(key string, value string, days int) *http.Cookie {
	// log.Printf("Making cookie %s with value %s for %d days\n", key, value, days)
	expiration := time.Now().AddDate(0, 0, days)

	return &http.Cookie{
		Name:    key,
		Value:   value,
		Expires: expiration,
		Path:    "/",
	}
}

func GenRandomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func OptionsFromQuery(hostItem HostConfigItem, values url.Values) []oauth2.AuthCodeOption {
	options := []oauth2.AuthCodeOption{}

	if values.Get("force") == "1" {
		options = append(options, oauth2.ApprovalForce)
	}

	if values.Get("offline") == "1" {
		options = append(options, oauth2.AccessTypeOffline)
	}

	// Since oauth2.AccessTypeOnline is default, we'll just leave.

	for _, row := range hostItem.Authentication.AddValues {
		options = append(options, oauth2.SetAuthURLParam(row[0], row[1]))
	}

	return options
}

func HtmlRedirect(url string) string {
	return fmt.Sprintf("<html><meta http-equiv=\"refresh\" content=\"0;url='%s'\" /></html>", url)
}

type User struct {
	Email string `json:"email"`
}

func getIdentityWithClient(url string, post bool, client *http.Client) (string, error) {
	var email *http.Response
	var err error

	if post {
		email, err = client.Post(url, "", nil)
	} else {
		email, err = client.Get(url)
	}

	if err != nil {
		return "", err
	}

	defer email.Body.Close()

	data, _ := ioutil.ReadAll(email.Body)

	var user User
	err = json.Unmarshal(data, &user)

	if err != nil {
		return "", err
	}

	return user.Email, nil
}

// End Util

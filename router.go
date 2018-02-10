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

	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
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

func BuildRouter(hci HostConfigItem, FQDN string) *httprouter.Router {
	hci.SaneDefaults()

	router := httprouter.New()

	if len(hci.Static.DirectoryMappings) > 0 {
		for _, pair := range hci.Static.DirectoryMappings {
			publicPath := fmt.Sprintf("%s*filepath", pair[0])
			fileSystemPath := pair[1]
			router.ServeFiles(publicPath, http.Dir(fileSystemPath))
		}
	}

	if hci.Static.StaticOnly {
		return router
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

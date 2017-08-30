package suez

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

type SuezReverseProxy struct {
	Proxy    *httputil.ReverseProxy
	HostItem *HostConfigItem
}

func (mrp SuezReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var identity string = ""

	cookie, cookie_err := r.Cookie(mrp.HostItem.Authorization.CookieName)

	if cookie_err == nil {
		var err error
		identity, err = Decrypt(
			mrp.HostItem.CookieEncryptionKey,
			cookie.Value,
		)
		if err == nil {
			identity = ""
		}
	}

	result := mrp.HostItem.Authorization.Gatekeeper.IsAllowed(
		mrp.HostItem,
		identity,
		r.RequestURI,
	)
	fmt.Println("Gatekeeper", identity, r.RequestURI, result)

	if result == GATEKEEPER_AUTH {
		fmt.Fprintf(w, HtmlRedirect("/%slogin?next=%s"), mrp.HostItem.RouteMount, r.RequestURI)
		return
	} else if result == GATEKEEPER_DENY {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Not authorized"))
		return
	}

	r.Header.Set("X-Suez-Identity", identity)

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

	if _, found := r.Header["Upgrade"]; found == true {
		handler := mrp.HostItem.CustomDialer.Dial(mrp.HostItem.Dial)
		handler.ServeHTTP(w, r)
		return
	} else if mrp.HostItem.AlwaysUseCustomDialer == true {
		handler := mrp.HostItem.CustomDialer.Dial(mrp.HostItem.Dial)
		handler.ServeHTTP(w, r)
		return
	} else {
		mrp.Proxy.ServeHTTP(w, r)
	}
}

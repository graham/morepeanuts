package suez

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

type ReverseProxy struct {
	Proxy    *httputil.ReverseProxy
	HostItem *HostConfigItem
}

func (mrp ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//defer timeTrack(time.Now(), fmt.Sprintf("ReverseProxy.ServeHTTP - %s - ", r.RequestURI))

	var identity string = ""
	var gatekeeper Gatekeeper = mrp.HostItem.Authorization.Gatekeeper

	cookie, cookie_err := r.Cookie(mrp.HostItem.Authorization.CookieName)

	if cookie_err == nil {
		identity, _ = Decrypt(
			mrp.HostItem.CookieEncryptionKey,
			cookie.Value,
		)
	}

	result := gatekeeper.IsAllowed(
		mrp.HostItem,
		identity,
		r,
	)

	if result == GATEKEEPER_AUTH {
		fmt.Fprintf(w, HtmlRedirect(
			"/%slogin?next=%s"),
			mrp.HostItem.RouteMount,
			r.RequestURI)
		return
	} else if result == GATEKEEPER_DENY {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Not Authorized"))
		return
	} else if result == GATEKEEPER_LIMIT {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("429 - Too Many Requests"))
		return
	} else if result == GATEKEEPER_BACKPRESSURE {
		// Delay before connection to backend is made.
		// could be to slow down a client, or to rate limit
		// an ip, or to help a backend recover.
		ms := gatekeeper.BackpressureTime(identity, r)
		var d time.Duration = time.Duration(ms) * time.Millisecond
		time.Sleep(d)
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

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/graham/suez"
	"github.com/julienschmidt/httprouter"
)

type CustomGatekeeper struct {
}

func (g CustomGatekeeper) IsAllowed(hci *suez.HostConfigItem, identity, fulluri string) suez.GatekeeperResponse {
	if len(identity) == 0 {
		return suez.GATEKEEPER_AUTH
	}

	if strings.HasSuffix(identity, "@domain.com") {
		return suez.GATEKEEPER_ALLOW
	}

	return suez.GATEKEEPER_DENY
}

func main() {
	hci := suez.HostConfigItem{}

	hci.Dial = "127.0.0.1:3000"
	hci.Authentication.ClientID = os.Getenv("CLIENTID")
	hci.Authentication.ClientSecret = os.Getenv("CLIENTSECRET")
	hci.Authorization.RequireAuth = true

	router := suez.BuildRouter(hci, "")

	router.GET("/", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "<html><body>Hello World</body></html>")
	})

	log.Fatal(http.ListenAndServe(
		fmt.Sprintf("%s:%d", "127.0.0.1", 9090),
		handlers.LoggingHandler(os.Stdout, router)),
	)

}

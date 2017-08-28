package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/graham/suez"
	"github.com/julienschmidt/httprouter"
)

func main() {
	hci := suez.HostConfigItem{}

	hci.Dial = os.GetEnv("DIAL")
	hci.Authentication.ClientID = os.GetEnv("CLIENTID")
	hci.Authentication.ClientSecret = os.GetEnv("CLIENTSECRET")
	hci.Authorization.RequireAuth = true

	router := suez.BuildRouter(hci, "")

	router.GET("/", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "<html><body>Hello World</body></html>")
	})

	log.Fatal(http.ListenAndServe(
		fmt.Sprintf("%s:%d", "127.0.0.1", 8080),
		handlers.LoggingHandler(os.Stdout, router)),
	)

}

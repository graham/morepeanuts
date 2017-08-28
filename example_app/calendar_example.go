package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"

	"github.com/gorilla/handlers"
	"github.com/julienschmidt/httprouter"

	google_calendar "google.golang.org/api/calendar/v3"
)

var config *oauth2.Config = &oauth2.Config{}

func main() {
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, INDEX_CONTENT)
		return
	})

	router.GET("/showme", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		cookie, err := r.Cookie("suez_authentication_key")

		if err != nil {
			// No auth cookie set, so we will report and bail out.
			fmt.Fprintf(w, `<html><body>
It looks like you have no auth data at all, so i'll redirect you to
<a href='/_/login?next=/showme&force=1'>/_/login?next=/showme</a>
</body></html>`)
			return
		}

		text, err := base64.URLEncoding.DecodeString(cookie.Value)

		if err != nil {
			fmt.Fprintf(w, `<html><body>
You somehow got us into a weird state, try logging out here:
<a href="/_/logout?next=/">Logout</a>
</body></html>`)
			return
		}

		var tok oauth2.Token
		json.Unmarshal([]byte(text), &tok)

		if tok.Valid() == false {
			fmt.Fprintf(w, `<html><body>
It looks like your token is no longer valid, you should re-request
<a href="/_/login?next=/showme">Here</a>
</body></html>`)
			return
		}

		client := config.Client(oauth2.NoContext, &tok)

		resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")

		if err != nil {
			fmt.Fprintf(w, `<html><body>
Failed to retrieve your client info.
</body></html>`)
		}

		b, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		fmt.Fprintf(
			w,
			`<html><body>Perfect! <br> The content of the user info request is <div style="padding:20px;">%s</div>`,
			bytes.NewReader(b),
		)

		service, err := google_calendar.New(client)

		if err != nil {
			fmt.Fprintf(w, "%s", err)
			return
		} else {
			t := time.Now().Format(time.RFC3339)
			events, err := service.Events.List("primary").ShowDeleted(false).
				SingleEvents(true).TimeMin(t).MaxResults(10).OrderBy("startTime").Do()

			if err != nil {
				fmt.Fprintf(w, "You haven't added calendar scope yet<br>")
				fmt.Fprintf(w, `
Now add a scope:
<a href="/_/add_scopes?next=/showme&scopes=https://www.googleapis.com/auth/calendar.readonly">Add Calendar Scope</a>
`)
				return
			}

			fmt.Fprintf(w, "<div style='padding: 30px'>")

			for _, i := range events.Items {
				var when string
				// If the DateTime is an empty string the Event is an all-day Event.
				// So only Date is available.
				if i.Start.DateTime != "" {
					when = i.Start.DateTime
				} else {
					when = i.Start.Date
				}
				fmt.Fprintf(w, "<div>%s (%s)</div>", when, i.Summary)
			}

			fmt.Fprintf(w, "</div>")
		}

		fmt.Fprintf(w, `</body></html>`)

		return
	})

	log.Fatal(http.ListenAndServe(
		fmt.Sprintf("%s:%d", "127.0.0.1", 3000),
		handlers.LoggingHandler(os.Stdout, router)),
	)
}

const INDEX_CONTENT = `
<html>
<body>
  Hello World, <a href='/_/login?next=/showme&force=1'>/_/login?next=/showme</a>
</body>
</html>
`

// The end.

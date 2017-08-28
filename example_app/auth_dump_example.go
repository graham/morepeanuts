package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/handlers"
	"github.com/julienschmidt/httprouter"
)

type Storage struct {
	sync.RWMutex
	Values map[string]string
}

func (s *Storage) Get(key string) (string, bool) {
	s.RLock()
	defer s.RUnlock()
	value, found := s.Values[key]
	return value, found
}

func (s *Storage) Set(key, value string) (string, bool) {
	s.Lock()
	defer s.Unlock()
	prevValue, found := s.Values[key]
	s.Values[key] = value
	return prevValue, found
}

type Value struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Error error  `json:"error"`
}

func getIdentity(r *http.Request) string {
	return r.Header.Get("X-Suez-Identity")
}

func main() {
	router := httprouter.New()

	store := Storage{
		Values: make(map[string]string),
	}

	store.Set("one", "1")
	store.Set("two", "2")
	store.Set("three", "3")

	router.GET("/", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "<html><body><table>")

		var count int = 0

		for key, value := range store.Values {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>", key, value)
			count += 1
		}

		fmt.Fprintf(w, "</table>")

		fmt.Fprintf(w, "<div>Found %d keys.</div>", count)
		fmt.Fprintf(w, "<div>Authed as %s</div>", getIdentity(r))
		fmt.Fprintf(w, "</body></html>")
	})

	router.GET("/get/:keyname", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		key := ps.ByName("keyname")
		value, _ := store.Get(key)

		var bdata []byte
		var error error

		bdata, error = json.Marshal(Value{Key: key, Value: value})

		if error != nil {
			bdata, _ = json.Marshal(Value{Key: key, Error: error})
		}

		fmt.Fprintf(w, string(bdata))
	})

	router.GET("/set/:keyname/:value", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		key := ps.ByName("keyname")
		value := ps.ByName("value")

		oldValue, _ := store.Get(key)
		store.Set(key, value)

		var bdata []byte
		var error error

		bdata, error = json.Marshal(Value{Key: key, Value: oldValue})

		if error != nil {
			bdata, _ = json.Marshal(Value{Key: key, Error: error})
		}

		fmt.Fprintf(w, string(bdata))

	})

	router.GET("/list", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		var results []Value = make([]Value, 0)

		for key, value := range store.Values {
			item := Value{Key: key, Value: value}
			results = append(results, item)
		}

		bdata, _ := json.Marshal(results)

		fmt.Fprintf(w, string(bdata))
	})

	router.GET("/list/:prefix", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		prefix := ps.ByName("prefix")

		var results []Value = make([]Value, 0)

		for key, value := range store.Values {
			if key[0:len(prefix)] == prefix {
				item := Value{Key: key, Value: value}
				results = append(results, item)
			}
		}

		bdata, _ := json.Marshal(results)

		fmt.Fprintf(w, string(bdata))
	})

	log.Fatal(http.ListenAndServe(
		fmt.Sprintf("%s:%d", "127.0.0.1", 8080),
		handlers.LoggingHandler(os.Stdout, router)),
	)

}

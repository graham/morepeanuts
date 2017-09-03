package suez

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/handlers"
)

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

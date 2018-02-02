package suez

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/handlers"
)

type ServerConfigItem struct {
	IsSecure                 bool       `toml:"secure"`
	RedirectSecure           bool       `toml:"redirect_secure"`
	Bind                     string     `toml:"bind"`
	Port                     int        `toml:"port"`
	SSLCertificates          [][]string `toml:"ssl_cert_pairs"`
	AutoRedirectInsecure     bool       `toml:"auto_redirect_insecure"`
	AutoReloadOnConfigChange bool       `toml:"auto_reload_on_config_change"`
	DomainToHostMap          map[string]HostConfigItem
	NotFound                 *HostConfigItem
	server                   *http.Server
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

func (sci *ServerConfigItem) Stop() {
	if sci.server == nil {
		fmt.Println("Server variable is null.")
		return
	}

	fmt.Println("Stopping")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	sci.server.Shutdown(ctx)
}

func (sci *ServerConfigItem) Listen() {
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
		cfg := &tls.Config{
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				//tls.X25519,
			},
		}

		for _, pair := range sci.SSLCertificates {
			cert, err := tls.LoadX509KeyPair(pair[0], pair[1])
			if err != nil {
				log.Fatal(err)
			}
			cfg.Certificates = append(cfg.Certificates, cert)
		}

		cfg.BuildNameToCertificate()

		sci.server = &http.Server{
			Addr:      fmt.Sprintf("%s:%d", sci.Bind, sci.Port),
			Handler:   handlers.LoggingHandler(os.Stdout, sci),
			TLSConfig: cfg,
		}

		sci.server.ListenAndServeTLS("", "")
	} else {
		sci.server = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", sci.Bind, sci.Port),
			Handler: handlers.LoggingHandler(os.Stdout, sci),
		}
		sci.server.ListenAndServe()
	}
}

func (sci *ServerConfigItem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var hostItem HostConfigItem
	var found bool
	var host string

	if strings.Contains(r.Host, ":") {
		result := strings.Split(r.Host, ":")
		host = result[0]
	} else {
		host = r.Host
	}

	if hostItem, found = sci.DomainToHostMap[host]; found == true {
		hostItem.Router.ServeHTTP(w, r)
	} else if hostItem, found = sci.RegexMatchHostRequest(host); found == true {
		hostItem.Router.ServeHTTP(w, r)
	} else {
		if sci.NotFound == nil {
			fmt.Fprintf(w, "Wasn't able to find: %s", r.RequestURI)
			return
		} else {
			sci.NotFound.Router.ServeHTTP(w, r)
			return
		}
	}
}

func (sci *ServerConfigItem) RegexMatchHostRequest(host string) (HostConfigItem, bool) {
	for _, v := range sci.DomainToHostMap {
		if v.RegexMatcher != nil {
			if v.RegexMatcher.MatchString(host) {
				return v, true
			}
		}
	}

	return HostConfigItem{}, false
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
			//fullDomain = fmt.Sprintf("%s:%d", hci.Domain, config.Server.Port)
			fullDomain = hci.Domain
		}

		if hci.Domain == "*" {
			config.Server.NotFound = &hci
			if config.Server.RedirctSecure == false {
				hci.OuterProtocol = "http"
			} else {
				hci.OuterProtocol = "https"
			}
			config.Server.NotFound.Router = BuildRouter(hci, "")
		} else {
			FQDN := fmt.Sprintf("%s://%s", protocol, fullDomain)
			hci.Router = BuildRouter(hci, FQDN)

			if hci.Domain[0] == '^' {
				c, err := regexp.Compile(hci.Domain)
				if err != nil {
					fmt.Printf("Failed to compile regex of %s -> %s\n", err, hci.Domain)
				} else {
					hci.RegexMatcher = c
				}
			}

			config.Server.DomainToHostMap[fullDomain] = hci
		}
	}

	return config.Server
}

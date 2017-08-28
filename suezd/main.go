package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/graham/suez"
)

func reportMemory() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	log.Printf("GoRoutines:    %d.\n", runtime.NumGoroutine())
	log.Printf("Heap           %0.2f mb.\n", float64(mem.HeapAlloc)/1024.0/1024.0)
	log.Printf("TotalGC:       %d\n", mem.PauseTotalNs)
}

func main() {
	done := make(chan bool, 1)

	b, err := ioutil.ReadFile("config.toml")
	if err != nil {
		panic(err)
	}

	var config struct {
		Server          suez.ServerConfigItem `toml:"server"`
		HostConfigItems []suez.HostConfigItem `toml:"host"`
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
			config.Server.NotFound.Router = suez.BuildRouter(hci, "")
		} else {
			FQDN := fmt.Sprintf("%s://%s", protocol, fullDomain)
			hci.Router = suez.BuildRouter(hci, FQDN)
			config.Server.DomainToHostMap[fullDomain] = hci
		}
	}

	go func() {
		for {
			reportMemory()
			time.Sleep(15 * time.Second)
		}
	}()

	config.Server.Listen()

	<-done
}

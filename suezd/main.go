package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/graham/suez"
)

func reportMemory() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	log.Printf("GoRoutines: %d | Heap: %0.2f mb | GCTime: %d",
		runtime.NumGoroutine(),
		float64(mem.HeapAlloc)/1024.0/1024.0,
		mem.PauseTotalNs,
	)
}

var FILENAME *string = flag.String("config", "config.toml", "config file name")

func main() {
	flag.Parse()
	log.SetFlags(0)

	done := make(chan bool, 1)

	go func() {
		for {
			reportMemory()
			time.Sleep(600 * time.Second)
		}
	}()

	var filename string = *FILENAME

	fmt.Printf("Loading config: %s\n", filename)

	server := suez.LoadServerFromConfig(filename)

	if server.AutoReloadOnConfigChange {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer watcher.Close()

		go func() {
			for {
				select {
				case event := <-watcher.Events:
					fmt.Println("File Event", event.Name)
					if event.Op&fsnotify.Write == fsnotify.Write &&
						event.Name == filename {
						server.Stop()
						server = suez.LoadServerFromConfig(filename)
						go func() {
							server.Listen()
						}()
					}
				case err := <-watcher.Errors:
					log.Println("error:", err)
				}
			}
		}()

		fmt.Println("adding watcher...")
		err = watcher.Add(filename)
	}

	go func() {
		server.Listen()
	}()

	<-done
}

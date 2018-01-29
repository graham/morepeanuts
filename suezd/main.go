package main

import (
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

func main() {
	var FILENAME string = "config.toml"

	done := make(chan bool, 1)

	go func() {
		for {
			reportMemory()
			time.Sleep(600 * time.Second)
		}
	}()

	server := suez.LoadServerFromConfig(FILENAME)

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
						event.Name == FILENAME {
						server.Stop()
						server = suez.LoadServerFromConfig(FILENAME)
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
		err = watcher.Add(FILENAME)
	}

	go func() {
		server.Listen()
	}()

	<-done
}

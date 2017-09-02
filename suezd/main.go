package main

import (
	"log"
	"runtime"
	"time"

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
	done := make(chan bool, 1)

	go func() {
		for {
			reportMemory()
			time.Sleep(15 * time.Second)
		}
	}()

	server := suez.LoadServerFromConfig("config.toml")
	server.Listen()

	<-done
}

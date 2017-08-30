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
	log.Printf("GoRoutines:    %d.\n", runtime.NumGoroutine())
	log.Printf("Heap           %0.2f mb.\n", float64(mem.HeapAlloc)/1024.0/1024.0)
	log.Printf("TotalGC:       %d\n", mem.PauseTotalNs)
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

package suez

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

type Logger interface {
	TimeTrack(start time.Time, tag string, r *http.Request);
	Log(s string);
}

type DefaultLogger struct {
	messages chan []byte
	fp *os.File
}

func NewDefaultLogger() DefaultLogger {
	fp, err := os.OpenFile("suez.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		panic(err)
	}

	message_queue := make(chan []byte, 20)

	dl := DefaultLogger{
		messages: message_queue,
		fp: fp,
	}

	go func() {
		for {
			message := <- message_queue
			fmt.Fprintf(fp, "%s\n", message)
		}
	}()

	return dl
}

func (l DefaultLogger) TimeTrack(start time.Time, tag string, r *http.Request) {
	elapsed := time.Since(start)
	l.messages <- []byte(fmt.Sprintf("%s took %s", tag, elapsed))
}

func (l DefaultLogger) Log(s string) {
	l.messages <- []byte(s)
}

func (l DefaultLogger) Logf(s string, args ...interface{}) {
	l.messages <- []byte(fmt.Sprintf(s, args...))
}

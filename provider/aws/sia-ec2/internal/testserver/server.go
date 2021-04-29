package testserver

import (
	"log"
	"net"
	"net/http"
)

type S struct {
	listener net.Listener
	addr     string
}

func (t *S) Start(h http.Handler) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panicln("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: h}
	t.listener = listener
	t.addr = listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
}

func (t *S) Stop() {
	t.listener.Close()
}

func (t *S) BaseUrl(version string) string {
	return "http://" + t.addr + "/" + version
}

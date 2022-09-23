// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmssvctoken

import (
	"fmt"
	"net"
	"net/http"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/dimfeld/httptreemux"
)

type handler func(src keySource) (pubKey []byte, rawResponse string, err error)

type server struct {
	l net.Listener
	h handler
}

func (s *server) run() {

	router := httptreemux.New()
	router.GET("/v1/domain/:domain/service/:name/publickey/:keyVersion", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		src := keySource{
			domain:     ps["domain"],
			name:       ps["name"],
			keyVersion: ps["keyVersion"],
		}
		key, resp, err := s.h(src)
		if err != nil {
			if rdlError, ok := err.(*rdl.ResourceError); ok {
				w.WriteHeader(rdlError.Code)
				w.Write([]byte(rdlError.Message))
			} else {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
			}
			return
		}
		if resp != "" {
			w.Write([]byte(resp))
			return
		}
		keyString := getEncoding().EncodeToString(key)
		w.Write([]byte(fmt.Sprintf(`{ "key": "%s" }`, keyString)))
	})
	http.Serve(s.l, router)
}

func (s *server) close() error {
	return s.l.Close()
}

func newServer(h handler) (s *server, baseURL string, err error) {

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", err
	}

	port := listener.Addr().(*net.TCPAddr).Port
	baseURL = fmt.Sprintf("http://:%d/v1", port)
	s = &server{
		l: listener,
		h: h,
	}
	return s, baseURL, nil
}

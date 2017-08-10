// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package devel

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/yahoo/athenz/utils/zpe-updater/util"

	"net"
)

func StartMockServer(endPoints map[string]string, metricEndPoints []string) string {
	router := mux.NewRouter()

	for key, val := range endPoints {
		router.HandleFunc(key, func(w http.ResponseWriter, r *http.Request) {

			io.WriteString(w, string(val))
		}).Methods("GET")
	}
	for _, domain := range metricEndPoints {
		router.HandleFunc(domain, func(w http.ResponseWriter, r *http.Request) {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Fatalf("Could not read the body, error: %v", err)
			}

			io.WriteString(w, string(body))
		}).Methods("POST")
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panicln("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: router}
	addr := listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
	return addr
}

func CreateFile(fileName, content string) error {
	if util.Exists(fileName) {
		err := os.Remove(fileName)
		if err != nil {
			return fmt.Errorf("Unable to remove file: %v, Error:%v", fileName, err)
		}
	}
	err := ioutil.WriteFile(fileName, []byte(content), 0755)
	if err != nil {
		return fmt.Errorf("Unable to write file: %v, Error:%v", fileName, err)
	}

	return nil
}

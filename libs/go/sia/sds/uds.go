//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package sds

import (
	"fmt"
	"inet.af/peercred"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

type Listener struct {
	net.Listener
}

type UdsConn struct {
	net.Conn
	ClientInfo ClientInfo
}

// StartUdsListener Start a Unix-Domain-Socket listener. We're going to create a simple
// wrapper struct for the Listener object since we want to intercept Accept calls
// and extract the caller's user and process ids. The client info object will then
// be passed to grpc as credentials.AuthInfo which can be accessed later from the
// stream context
func StartUdsListener(udsPath string) (net.Listener, error) {

	err := os.MkdirAll(filepath.Dir(udsPath), 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to make the directory for the Unix-Domain-Socket listener on path %q: %v", udsPath, err)
	}

	// Prepare: delete any existing Unix-Domain-Socket.
	os.Remove(udsPath)

	// Listen on the Unix-Domain-Socket.
	udsListener, err := net.Listen("unix", udsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listed to Unix-Domain-Socket listener on path %q: %v", udsPath, err)
	}

	err = os.Chmod(udsPath, os.ModePerm)
	if err != nil {
		udsListener.Close()
		return nil, fmt.Errorf("failed to set permissions to Unix-Domain-Socket on path %q: %v", udsPath, err)
	}

	// Server is ready to accept UDS requests.
	log.Printf("Unix-Domain-Socket listener is ready on path: %s\n", udsPath)
	return &Listener{
		Listener: udsListener,
	}, nil
}

func (listener *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := listener.Listener.Accept()
		if err != nil {
			return conn, err
		}
		return &UdsConn{
			Conn:       conn,
			ClientInfo: getUdsUserDetails(conn),
		}, nil
	}
}

func (listener *Listener) Close() error {
	return listener.Listener.Close()
}

func (listener *Listener) Addr() net.Addr {
	return listener.Listener.Addr()
}

// Get the Unix-Domain-Socket's user and process ids
func getUdsUserDetails(connection net.Conn) ClientInfo {

	var clientInfo ClientInfo

	// Get uid from UDS connection.
	credentials, err := peercred.Get(connection)
	if err != nil {
		return clientInfo
	}
	userId, ok := credentials.UserID()
	if !ok {
		log.Println("unable to obtain connection user id")
	} else {
		uid, err := strconv.Atoi(userId)
		if err != nil {
			log.Printf("unable to obtain convert user id: %s, %v\n", userId, err)
		} else {
			clientInfo.UserID = uid
		}
	}
	clientInfo.PID, ok = credentials.PID()
	if !ok {
		log.Println("unable to obtain connection pid")
	}
	return clientInfo
}

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
	"errors"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	envoySecret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"log"
	"os"
)

func StartGrpcServer(opts *options.Options, certUpdates chan bool) error {

	listener, err := StartUdsListener(opts.SDSUdsPath)
	if err != nil {
		return fmt.Errorf("unable to start uds listener for %s, error: %v", opts.SDSUdsPath, err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer(
		grpc.Creds(NewCredentials()),
	)

	serverHandler := NewServerHandler(opts)
	go notifyCertificateUpdates(serverHandler, certUpdates)

	envoySecret.RegisterSecretDiscoveryServiceServer(grpcServer, serverHandler)

	errChan := make(chan error)
	go func() {
		errChan <- grpcServer.Serve(listener)
	}()

	select {
	case err = <-errChan:
		log.Println("Stopping GRPC SDS server...")
		grpcServer.Stop()
		if _, err := os.Stat(opts.SDSUdsPath); err == nil {
			os.Remove(opts.SDSUdsPath)
		}
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
	}

	return err
}

func notifyCertificateUpdates(serverHandler *ServerHandler, updates <-chan bool) {
	for {
		select {
		case <-updates:
			serverHandler.NotifySubscribers()
		}
	}
}

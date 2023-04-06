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
	"context"
	"errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"net"
)

type grpcCredentials struct{}

func NewCredentials() credentials.TransportCredentials {
	return &grpcCredentials{}
}

func AthenzGrpcServerName() string {
	return "athenz-sia-sds"
}

func (creds *grpcCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn.Close()
	return conn, ClientInfo{}, errors.New("client handshake not expected")
}

func (creds *grpcCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	udsConn, ok := conn.(*UdsConn)
	if !ok {
		udsConn.Close()
		return conn, ClientInfo{}, errors.New("connection type is not uds")
	}

	return udsConn, udsConn.ClientInfo, nil
}

func (creds *grpcCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: ClientAuthType(),
		ServerName:       AthenzGrpcServerName(),
	}
}

func (creds *grpcCredentials) Clone() credentials.TransportCredentials {
	clone := *creds
	return &clone
}

func (creds *grpcCredentials) OverrideServerName(_ string) error {
	return nil
}

func ClientInfoFromContext(ctx context.Context) ClientInfo {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ClientInfo{}
	}
	clientInfo, ok := peer.AuthInfo.(ClientInfo)
	if !ok {
		return ClientInfo{}
	}
	return clientInfo
}

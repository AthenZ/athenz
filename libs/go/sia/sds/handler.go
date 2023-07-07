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
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/options"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	envoyCore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyTls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoyDiscovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoySecret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"io"
	"log"
	"os"
	"sync"
)

type ServerHandler struct {
	Mutex       sync.RWMutex
	Options     *options.Options
	Subscribers map[string]*Subscriber
}

func NewServerHandler(opts *options.Options) *ServerHandler {
	return &ServerHandler{
		Options:     opts,
		Subscribers: make(map[string]*Subscriber),
		Mutex:       sync.RWMutex{},
	}
}

func (handler *ServerHandler) StreamSecrets(stream envoySecret.SecretDiscoveryService_StreamSecretsServer) error {

	sub := handler.subscribeToCertUpdates()
	defer handler.removeSubscriber(sub)

	clientInfo := ClientInfoFromContext(stream.Context())
	log.Printf("StreamSecrets: %s: client info: %v\n", sub.GetId(), clientInfo)

	reqChan := make(chan *envoyDiscovery.DiscoveryRequest, 1)
	errChan := make(chan error, 1)

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				log.Printf("StreamSecrets: %s: receiving error: %v\n", sub.GetId(), err)
				if status.Code(err) == codes.Canceled || errors.Is(err, io.EOF) {
					log.Printf("StreamSecrets: %s: resetting error...\n", sub.GetId())
					err = nil
				}
				errChan <- err
				return
			}
			reqChan <- req
		}
	}()

	var curReq *envoyDiscovery.DiscoveryRequest
	for {
		select {
		case newReq := <-reqChan:

			if curReq == nil {
				log.Printf("StreamSecrets: %s: processing new request\n", sub.GetId())
			} else {
				log.Printf("StreamSecrets: %s: processing request: version: %s, nonce: %s\n", sub.GetId(), newReq.GetVersionInfo(), newReq.GetResponseNonce())
			}

			// if envoy reported any errors then we're just going to log them,
			// but we won't stop processing any requests or close connections
			if newReq.ErrorDetail != nil {
				log.Printf("StreamSecrets: %s: envoy reported error: %s\n", sub.GetId(), newReq.ErrorDetail.Message)
			}

			// validate the request nonce and if mismatch, ignore the request
			if !sub.ValidateResponseNonce(newReq.ResponseNonce) {
				continue
			}

			// validate version information
			if !sub.ValidateVersionInfo(newReq.VersionInfo) {
				continue
			}

			// after the first request we should only process the requests
			// if the list of requested resource names has changed
			if curReq != nil && !resourceNamesChanged(curReq.ResourceNames, newReq.ResourceNames) {
				continue
			}

			// set and process the new request
			curReq = newReq

		case <-sub.GetCertUpdates():
			sub.IncrementVersion()
			// in case we receive an update before an actual request is processed
			// we should ignore the update
			if curReq == nil {
				continue
			}
			log.Printf("StreamSecrets: %s: pushing updated certificates to envoy...\n", sub.GetId())

		case err := <-errChan:
			return err
		}

		resp, err := handler.getStreamResponse(sub, clientInfo, curReq)
		if err != nil {
			log.Printf("StreamSecrets: %s: unable to generate stream response: %v\n", sub.GetId(), err)
			return err
		}

		if err := stream.Send(resp); err != nil {
			log.Printf("StreamSecrets: %s: secret send error: %v\n", sub.GetId(), err)
			return err
		}

		// update the last nonce successfully sent to client
		sub.SetResponseNonce(resp.GetNonce())
	}
}

func (handler *ServerHandler) DeltaSecrets(envoySecret.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented, "Unimplemented Method")
}

func (handler *ServerHandler) FetchSecrets(ctx context.Context, req *envoyDiscovery.DiscoveryRequest) (*envoyDiscovery.DiscoveryResponse, error) {

	clientInfo := ClientInfoFromContext(ctx)
	log.Printf("FetchSecrets: client info: %v\n", clientInfo)

	resp, err := handler.getFetchResponse(clientInfo, req)
	if err != nil {
		log.Printf("FetchSecrets: unable to generate response: %v\n", err)
		return nil, err
	}

	return resp, nil
}

func resourceNamesChanged(currentResources []string, newResources []string) bool {
	// if the length of arrays are different, then we know there is a change
	if len(currentResources) != len(newResources) {
		return true
	}
	// typically, we'll only get a small number of resources,
	// but we'll use a map/set to see if there is a change
	var resourceMap = make(map[string]bool)
	for _, resource := range currentResources {
		resourceMap[resource] = true
	}
	for _, resource := range newResources {
		if !resourceMap[resource] {
			return true
		}
	}
	return false
}

func (handler *ServerHandler) getFetchResponse(info ClientInfo, req *envoyDiscovery.DiscoveryRequest) (*envoyDiscovery.DiscoveryResponse, error) {

	resp := &envoyDiscovery.DiscoveryResponse{
		TypeUrl: req.TypeUrl,
	}

	err := handler.getResponse(req, info, "", resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (handler *ServerHandler) getStreamResponse(sub *Subscriber, info ClientInfo, req *envoyDiscovery.DiscoveryRequest) (*envoyDiscovery.DiscoveryResponse, error) {

	resp := &envoyDiscovery.DiscoveryResponse{
		TypeUrl:     req.TypeUrl,
		VersionInfo: sub.GetVersionInfo(),
	}

	// provide a nonce for streaming requests
	var err error
	if resp.Nonce, err = util.Nonce(); err != nil {
		return nil, err
	}

	err = handler.getResponse(req, info, sub.GetId(), resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (handler *ServerHandler) getResponse(req *envoyDiscovery.DiscoveryRequest, info ClientInfo, subId string, resp *envoyDiscovery.DiscoveryResponse) error {

	for _, resource := range req.ResourceNames {
		log.Printf("Response: %s: requesting secret: %s\n", subId, resource)
	}

	// parse the requested resource name
	for _, spiffeUri := range req.ResourceNames {
		// let's check if this is a CA Bundle certificate spiffe uri
		_, namespace, name := util.ParseCASpiffeUri(spiffeUri)
		if namespace != "" && name != "" {
			tlsCABundle, err := handler.getTLSCABundleSecret(spiffeUri, namespace, name)
			if err != nil {
				return err
			}
			resp.Resources = append(resp.Resources, tlsCABundle)
		} else {
			_, _, domain, service := util.ParseServiceSpiffeUri(spiffeUri)
			if domain == "" || service == "" {
				log.Printf("Response: %s: unable to parse spiffe uri: %s\n", subId, spiffeUri)
				continue
			}
			// authenticate the request
			svc, err := handler.authenticateRequest(info, req.GetNode(), domain, service)
			if err != nil {
				log.Printf("Response: %s: unable to authenticate the request: %v\n", subId, err)
				continue
			}
			tlsCertificate, err := handler.getTLSCertificateSecret(spiffeUri, svc)
			if err != nil {
				log.Printf("Response: %s: unable to build envoyTls certificate: %v\n", subId, err)
				continue
			}
			resp.Resources = append(resp.Resources, tlsCertificate)
		}
	}
	return nil
}

func (handler *ServerHandler) subscribeToCertUpdates() *Subscriber {

	handler.Mutex.Lock()
	subscriber := NewSubscriber()
	handler.Subscribers[subscriber.GetId()] = subscriber
	handler.Mutex.Unlock()

	log.Printf("Subscription: %s: registering new subscriber\n", subscriber.GetId())
	return subscriber
}

func (handler *ServerHandler) removeSubscriber(subscriber *Subscriber) {

	log.Printf("Subscription: %s: removing subscriber\n", subscriber.GetId())

	handler.Mutex.Lock()
	delete(handler.Subscribers, subscriber.GetId())
	defer handler.Mutex.Unlock()

	subscriber.Close()
}

func (handler *ServerHandler) NotifySubscribers() {

	handler.Mutex.RLock()
	for _, subscriber := range handler.Subscribers {
		subscriber.Notify()
	}
	handler.Mutex.RUnlock()
}

func (handler *ServerHandler) authenticateRequest(info ClientInfo, node *envoyCore.Node, domain, service string) (*options.Service, error) {

	if domain != handler.Options.Domain {
		return nil, fmt.Errorf("invalid domain name: %s, expected: %s", domain, handler.Options.Domain)
	}
	for _, svc := range handler.Options.Services {
		if svc.Name == service {
			if svc.SDSUdsUid != info.UserID {
				return nil, fmt.Errorf("invalid uid: %d, expected: %d", info.UserID, svc.SDSUdsUid)
			}
			nodeId := ""
			if node != nil {
				nodeId = node.GetId()
			}
			if svc.SDSNodeId != "" && svc.SDSNodeId != nodeId {
				return nil, fmt.Errorf("invalid node id: %s, expected: %s", nodeId, svc.SDSNodeId)
			}
			nodeCluster := ""
			if node != nil {
				nodeCluster = node.GetCluster()
			}
			if svc.SDSNodeCluster != "" && svc.SDSNodeCluster != nodeCluster {
				return nil, fmt.Errorf("invalid node cluster: %s, expected: %s", nodeCluster, svc.SDSNodeCluster)
			}
			return &svc, nil
		}
	}
	return nil, fmt.Errorf("unknown service: %s", service)
}

func (handler *ServerHandler) getTLSCertificateSecret(spiffeUri string, svc *options.Service) (*anypb.Any, error) {

	keyFile := util.GetSvcKeyFileName(handler.Options.KeyDir, svc.KeyFilename, handler.Options.Domain, svc.Name)
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	certFile := util.GetSvcCertFileName(handler.Options.CertDir, svc.CertFilename, handler.Options.Domain, svc.Name)
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return anypb.New(&envoyTls.Secret{
		Name: spiffeUri,
		Type: &envoyTls.Secret_TlsCertificate{
			TlsCertificate: &envoyTls.TlsCertificate{
				CertificateChain: &envoyCore.DataSource{
					Specifier: &envoyCore.DataSource_InlineBytes{
						InlineBytes: certPEM,
					},
				},
				PrivateKey: &envoyCore.DataSource{
					Specifier: &envoyCore.DataSource_InlineBytes{
						InlineBytes: keyPEM,
					},
				},
			},
		},
	})
}

func (handler *ServerHandler) getTLSCABundleSecret(spiffeUri, caNamespace, caName string) (*anypb.Any, error) {

	//we support a single namespace athenz with bundle name default
	if caNamespace != "athenz" || caName != "default" {
		return nil, fmt.Errorf("unknown TLS CA Bundle: %s\n", spiffeUri)
	}
	caCertsPEM, err := os.ReadFile(handler.Options.AthenzCACertFile)
	if err != nil {
		return nil, err
	}
	configTrustDomains := []*envoyTls.SPIFFECertValidatorConfig_TrustDomain{
		{
			Name: caName,
			TrustBundle: &envoyCore.DataSource{
				Specifier: &envoyCore.DataSource_InlineBytes{
					InlineBytes: caCertsPEM,
				},
			},
		},
	}

	typedConfig, err := anypb.New(&envoyTls.SPIFFECertValidatorConfig{
		TrustDomains: configTrustDomains,
	})
	if err != nil {
		return nil, err
	}

	return anypb.New(&envoyTls.Secret{
		Name: spiffeUri,
		Type: &envoyTls.Secret_ValidationContext{
			ValidationContext: &envoyTls.CertificateValidationContext{
				CustomValidatorConfig: &envoyCore.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: typedConfig,
				},
			},
		},
	})
}

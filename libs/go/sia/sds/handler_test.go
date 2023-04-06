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
	"github.com/AthenZ/athenz/libs/go/sia/options"
	envoyCore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyDiscovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"strings"
	"testing"
)

func TestResourceNamesChanged(test *testing.T) {
	curList := []string{"abc", "bcd", "cde"}
	newList := []string{"abc", "bcd", "cde"}
	if resourceNamesChanged(curList, newList) {
		test.Errorf("identical resource lists marked as changed")
	}

	curList = []string{"abc", "bcd", "cde"}
	newList = []string{"abc", "bcd"}
	if !resourceNamesChanged(curList, newList) {
		test.Errorf("different size resource lists marked as not changed")
	}

	curList = []string{"abc", "bcd", "cde"}
	newList = []string{"abc", "bcd", "def"}
	if !resourceNamesChanged(curList, newList) {
		test.Errorf("different value / same size resource lists marked as not changed")
	}
}

func TestGetResponseInvalidUri(test *testing.T) {
	handler := NewServerHandler(&options.Options{})
	req := envoyDiscovery.DiscoveryRequest{
		ResourceNames: []string{"spiffe://athenz/invalid"},
	}
	resp := envoyDiscovery.DiscoveryResponse{}
	err := handler.getResponse(&req, ClientInfo{}, "", &resp)
	if err != nil {
		test.Errorf("unexpected error returned: %v", err)
	}
	if len(resp.Resources) != 0 {
		test.Errorf("unexpected response objects created")
	}
}

func TestSubscriptionChanges(test *testing.T) {
	handler := NewServerHandler(&options.Options{})
	if len(handler.Subscribers) != 0 {
		test.Errorf("new handler has some subscribers")
	}
	sub := handler.subscribeToCertUpdates()
	if handler.Subscribers[sub.GetId()] == nil {
		test.Errorf("new subscriber is not in the list")
	}
	id := sub.GetId()
	handler.removeSubscriber(sub)
	if handler.Subscribers[id] != nil {
		test.Errorf("removed subscriber is still in the list")
	}
}

func TestSubscriptionNotifications(test *testing.T) {
	handler := NewServerHandler(&options.Options{})
	sub := handler.subscribeToCertUpdates()
	handler.NotifySubscribers()
	updates := <-sub.GetCertUpdates()
	if !updates {
		test.Errorf("subscriber update flag is not set correctly")
	}
	handler.removeSubscriber(sub)
}

func TestAuthenticateRequestMismatchDomain(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain: "athenz",
	})
	_, err := handler.authenticateRequest(ClientInfo{}, nil, "sports", "api")
	if err == nil {
		test.Errorf("invalid domain was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "invalid domain name") {
		test.Errorf("error does not include expected invalid domain message: %s", err.Error())
	}
}

func TestAuthenticateRequestUnknownService(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain:   "athenz",
		Services: []options.Service{{Name: "backend"}},
	})
	_, err := handler.authenticateRequest(ClientInfo{}, nil, "athenz", "api")
	if err == nil {
		test.Errorf("unknown service was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "unknown service") {
		test.Errorf("error does not include expected unknown service message: %s", err.Error())
	}
}

func TestAuthenticateRequestMismatchUid(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain:   "athenz",
		Services: []options.Service{{Name: "api", SDSUdsUid: 124}},
	})
	_, err := handler.authenticateRequest(ClientInfo{UserID: 123}, nil, "athenz", "api")
	if err == nil {
		test.Errorf("mismatched uid was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "invalid uid") {
		test.Errorf("error does not include expected invalid uid message: %s", err.Error())
	}
}

func TestAuthenticateRequestMismatchNodeId(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain:   "athenz",
		Services: []options.Service{{Name: "api", SDSUdsUid: 123, SDSNodeId: "id1"}},
	})
	// first try with nil node
	_, err := handler.authenticateRequest(ClientInfo{UserID: 123}, nil, "athenz", "api")
	if err == nil {
		test.Errorf("mismatched node id was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "invalid node id: ,") {
		test.Errorf("error does not include expected invalid node id message: %s", err.Error())
	}
	// now with a node with mismatched nodeid
	_, err = handler.authenticateRequest(ClientInfo{UserID: 123}, &envoyCore.Node{Id: "id2"}, "athenz", "api")
	if err == nil {
		test.Errorf("mismatched node id was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "invalid node id: id2,") {
		test.Errorf("error does not include expected invalid node id message: %s", err.Error())
	}
}

func TestAuthenticateRequestMismatchNodeCluster(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain:   "athenz",
		Services: []options.Service{{Name: "api", SDSUdsUid: 123, SDSNodeCluster: "cluster1"}},
	})
	// first try with nil node
	_, err := handler.authenticateRequest(ClientInfo{UserID: 123}, nil, "athenz", "api")
	if err == nil {
		test.Errorf("mismatched node cluster was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "invalid node cluster: ,") {
		test.Errorf("error does not include expected invalid node cluster message: %s", err.Error())
	}
	// now with a node with mismatched node cluster
	_, err = handler.authenticateRequest(ClientInfo{UserID: 123}, &envoyCore.Node{Id: "id1", Cluster: "cluster2"}, "athenz", "api")
	if err == nil {
		test.Errorf("mismatched node cluster was correctly authenticated")
	}
	if !strings.Contains(err.Error(), "invalid node cluster: cluster2,") {
		test.Errorf("error does not include expected invalid node cluster message: %s", err.Error())
	}
}

func TestAuthenticateRequestMatchNilNode(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain:   "athenz",
		Services: []options.Service{{Name: "api", SDSUdsUid: 123}},
	})
	_, err := handler.authenticateRequest(ClientInfo{UserID: 123}, nil, "athenz", "api")
	if err != nil {
		test.Errorf("valid requested was not correctly authenticated: %v", err)
	}
}

func TestAuthenticateRequestMatchWithNode(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		Domain:   "athenz",
		Services: []options.Service{{Name: "api", SDSUdsUid: 123, SDSNodeId: "id1", SDSNodeCluster: "cluster1"}},
	})
	_, err := handler.authenticateRequest(ClientInfo{UserID: 123}, &envoyCore.Node{Id: "id1", Cluster: "cluster1"}, "athenz", "api")
	if err != nil {
		test.Errorf("valid requested was not correctly authenticated: %v", err)
	}
}

func TestGetTLSCertificateSecretUnknownPrivateKey(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		KeyDir:  "data",
		CertDir: "data",
		Domain:  "athenz",
	})
	svc := options.Service{
		Name: "unknown",
	}
	_, err := handler.getTLSCertificateSecret("spiffe://athenz/sa/api", &svc)
	if err == nil {
		test.Errorf("was able to generate certificate for unknown key file")
	}
}

func TestGetTLSCertificateSecretUnknownCertificate(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		KeyDir:  "data",
		CertDir: "data",
		Domain:  "athenz",
	})
	svc := options.Service{
		Name:         "api",
		KeyFilename:  "unknown",
		CertFilename: "unknown",
	}
	_, err := handler.getTLSCertificateSecret("spiffe://athenz/sa/api", &svc)
	if err == nil {
		test.Errorf("was able to generate certificate for unknown cert file")
	}
}

func TestGetTLSCertificateSecret(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		KeyDir:  "data",
		CertDir: "data",
		Domain:  "athenz",
	})
	svc := options.Service{
		Name: "api",
	}
	_, err := handler.getTLSCertificateSecret("spiffe://athenz/sa/api", &svc)
	if err != nil {
		test.Errorf("unable to generate certificate secret: %v", err)
	}
}

func TestGetTLSCABundleSecretInvalidNamespace(test *testing.T) {
	handler := NewServerHandler(&options.Options{})
	_, err := handler.getTLSCABundleSecret("spiffe://athenz/ca/default", "coretech", "default")
	if err == nil {
		test.Errorf("certificate generated for invalid namespace")
	}
}

func TestGetTLSCABundleSecretInvalidName(test *testing.T) {
	handler := NewServerHandler(&options.Options{})
	_, err := handler.getTLSCABundleSecret("spiffe://athenz/ca/default", "athenz", "primary")
	if err == nil {
		test.Errorf("certificate generated for invalid name")
	}
}

func TestGetTLSCABundleSecretInvalidFile(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		AthenzCACertFile: "unknown-file",
	})
	_, err := handler.getTLSCABundleSecret("spiffe://athenz/ca/default", "athenz", "default")
	if err == nil {
		test.Errorf("certificate generated for invalid filename")
	}
}

func TestGetTLSCABundleSecret(test *testing.T) {
	handler := NewServerHandler(&options.Options{
		AthenzCACertFile: "data/ca.cert.pem",
	})
	_, err := handler.getTLSCABundleSecret("spiffe://athenz/ca/default", "athenz", "default")
	if err != nil {
		test.Errorf("unable to generate valid bundle: %v", err)
	}
}

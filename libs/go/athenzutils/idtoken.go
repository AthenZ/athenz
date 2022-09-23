// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"encoding/json"
	"errors"
	"github.com/AthenZ/athenz/clients/go/zts"
	"gopkg.in/square/go-jose.v2/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"strings"
	"time"
)

func FetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, redirectUri, scope, nonce, state, keyType string, fullArn *bool, proxy bool) (string, error) {

	client, err := ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	if err != nil {
		return "", err
	}
	client.DisableRedirect = true

	// request an id token
	_, location, err := client.GetOIDCResponse("id_token", zts.ServiceName(clientId), redirectUri, scope, zts.EntityName(state), zts.EntityName(nonce), zts.SimpleName(keyType), fullArn)
	if err != nil {
		return "", err
	}

	//the format of the location header is <redirect-uri>#id_token=<token>&state=<state>
	idTokenLabel := "#id_token="
	startIdx := strings.Index(location, idTokenLabel)
	if startIdx == -1 {
		return "", errors.New("location header does not contain id_token field")
	}
	idToken := location[startIdx+len(idTokenLabel):]
	endIdx := strings.Index(idToken, "&state")
	if endIdx != -1 {
		idToken = idToken[:endIdx]
	}
	return idToken, nil
}

func FetchIdTokenExpiryTime(idToken string) (*time.Time, error) {
	tok, err := jwt.ParseSigned(idToken)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	err = tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, err
	}
	sec := claims["exp"].(float64)
	expiryTime := time.Unix(int64(sec), 0)
	return &expiryTime, nil
}

func GetK8SClientAuthCredential(idToken string) (string, error) {
	expiryTime, err := FetchIdTokenExpiryTime(idToken)
	if err != nil {
		return "", err
	}
	metaType := metav1.TypeMeta{
		Kind:       "ExecCredential",
		APIVersion: "client.authentication.k8s.io/v1",
	}
	metaExpiryTime := metav1.NewTime(*expiryTime)
	status := authv1.ExecCredentialStatus{
		Token:               idToken,
		ExpirationTimestamp: &metaExpiryTime,
	}
	creds := authv1.ExecCredential{
		TypeMeta: metaType,
		Status:   &status,
	}
	output, err := json.Marshal(creds)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

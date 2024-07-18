// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"encoding/json"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"time"
)

func FetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, scope, nonce, state, keyType string, fullArn *bool, proxy bool, expireTime *int32, roleInAudClaim, allScopesPresent *bool) (string, error) {

	client, err := ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	if err != nil {
		return "", err
	}
	client.DisableRedirect = true

	// request an id token
	response, _, err := client.GetOIDCResponse("id_token", zts.ServiceName(clientId), "", scope, zts.EntityName(state), zts.EntityName(nonce), zts.SimpleName(keyType), fullArn, expireTime, "json", roleInAudClaim, allScopesPresent)
	if err != nil {
		return "", err
	}
	return response.Id_token, nil
}

func FetchIdTokenExpiryTime(idToken string) (*time.Time, error) {
	signatureAlgorithms := []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}
	tok, err := jwt.ParseSigned(idToken, signatureAlgorithms)
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

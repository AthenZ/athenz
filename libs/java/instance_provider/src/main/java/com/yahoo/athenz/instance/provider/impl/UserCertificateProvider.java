/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.instance.provider.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.token.jwts.OpenIdConfiguration;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.athenz.zts.AccessTokenResponse;

import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class UserCertificateProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserCertificateProvider.class);

    static final String USER_CERT_PROP_CONFIG_ENDPOINT     = "athenz.zts.user_cert.idp_config_endpoint";
    static final String USER_CERT_PROP_TOKEN_ENDPOINT      = "athenz.zts.user_cert.idp_token_endpoint";
    static final String USER_CERT_PROP_JWKS_ENDPOINT       = "athenz.zts.user_cert.idp_jwks_endpoint";
    static final String USER_CERT_PROP_CLIENT_ID           = "athenz.zts.user_cert.idp_client_id";
    static final String USER_CERT_PROP_REDIRECT_URI        = "athenz.zts.user_cert.idp_redirect_uri";
    static final String USER_CERT_PROP_AUDIENCE            = "athenz.zts.user_cert.idp_audience";
    static final String USER_CERT_PROP_CONNECT_TIMEOUT     = "athenz.zts.user_cert.connect_timeout";
    static final String USER_CERT_PROP_READ_TIMEOUT        = "athenz.zts.user_cert.read_timeout";
    static final String USER_CERT_PROP_USER_NAME_CLAIM     = "athenz.zts.user_cert.user_name_claim";

    static final String USER_CERT_PROP_CLIENT_SECRET_APP      = "athenz.zts.user_cert.idp_client_secret_app";
    static final String USER_CERT_PROP_CLIENT_SECRET_KEYGROUP = "athenz.zts.user_cert.idp_client_secret_keygroup";
    static final String USER_CERT_PROP_CLIENT_SECRET_KEYNAME  = "athenz.zts.user_cert.idp_client_secret_keyname";

    static final String CODE_PREFIX = "code=";
    static final String FIELD_ACCESS_TOKEN = "access_token";

    static final String DEFAULT_REDIRECT_URI = "http://localhost:3222/oauth2/callback";

    String tokenEndpoint;
    String clientId;
    String clientSecret;
    String redirectUri;
    String userNameClaim;
    String audience;
    int connectTimeout;
    int readTimeout;

    PrivateKeyStore privateKeyStore;
    JwtsSigningKeyResolver signingKeyResolver;
    ObjectMapper jsonMapper = new ObjectMapper();

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void setPrivateKeyStore(PrivateKeyStore privateKeyStore) {
        this.privateKeyStore = privateKeyStore;
    }

    @Override
    public void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore)
            throws ProviderResourceException {

        String jwksEndpoint = null;
        final String configEndpoint = System.getProperty(USER_CERT_PROP_CONFIG_ENDPOINT);
        if (!StringUtil.isEmpty(configEndpoint)) {
            JwtsHelper helper = new JwtsHelper();
            OpenIdConfiguration openIdConfig = helper.extractOpenIdConfiguration(configEndpoint, sslContext, null);
            if (openIdConfig != null) {
                tokenEndpoint = openIdConfig.getTokenEndpoint();
                jwksEndpoint = openIdConfig.getJwksUri();
            }
        }

        if (StringUtil.isEmpty(tokenEndpoint)) {
            tokenEndpoint = System.getProperty(USER_CERT_PROP_TOKEN_ENDPOINT);
            if (StringUtil.isEmpty(tokenEndpoint)) {
                throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                        "IdP token endpoint not configured");
            }
        }

        if (StringUtil.isEmpty(jwksEndpoint)) {
            jwksEndpoint = System.getProperty(USER_CERT_PROP_JWKS_ENDPOINT);
            if (StringUtil.isEmpty(jwksEndpoint)) {
                throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                        "IdP jwks endpoint not configured");
            }
        }
        signingKeyResolver = new JwtsSigningKeyResolver(jwksEndpoint, null);

        clientId = System.getProperty(USER_CERT_PROP_CLIENT_ID);
        if (StringUtil.isEmpty(clientId)) {
            throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                    "IdP client id not configured");
        }

        clientSecret = getClientSecret();
        redirectUri = System.getProperty(USER_CERT_PROP_REDIRECT_URI, DEFAULT_REDIRECT_URI);

        // extract audience. if specified, the value must match the audience in the token
        
        audience = System.getProperty(USER_CERT_PROP_AUDIENCE);

        // extract connection and read timeouts
        
        connectTimeout = Integer.parseInt(System.getProperty(USER_CERT_PROP_CONNECT_TIMEOUT, "10000"));
        readTimeout = Integer.parseInt(System.getProperty(USER_CERT_PROP_READ_TIMEOUT, "15000"));

        // extract user name claim. by default, use the subject claim
        // but it's possible that the IdP uses a different claim for the user name
        // in that case, the user can configure the claim name here
        
        userNameClaim = System.getProperty(USER_CERT_PROP_USER_NAME_CLAIM);
    }

    String getClientSecret() {

        if (privateKeyStore == null) {
            return "";
        }

        final String appName = System.getProperty(USER_CERT_PROP_CLIENT_SECRET_APP, "");
        final String keygroupName = System.getProperty(USER_CERT_PROP_CLIENT_SECRET_KEYGROUP, "");
        final String keyName = System.getProperty(USER_CERT_PROP_CLIENT_SECRET_KEYNAME, "");

        if (StringUtil.isEmpty(keyName)) {
            return "";
        }

        char[] secret = privateKeyStore.getSecret(appName, keygroupName, keyName);
        return (secret != null) ? new String(secret) : "";
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) throws ProviderResourceException {

        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw forbiddenError("Attestation data not provided");
        }

        final String userName = confirmation.getService();
        if (StringUtil.isEmpty(userName)) {
            throw forbiddenError("User name not provided in confirmation");
        }

        // the attestation data is the callback query string from the OAuth2 flow
        // which contains code and state parameters - extract the code

        final String authCode = extractAuthCode(attestationData);
        if (StringUtil.isEmpty(authCode)) {
            throw forbiddenError("Unable to extract authorization code from attestation data");
        }

        // exchange the authorization code with the IdP token endpoint

        AccessToken accessTokenObject;
        final String accessTokenString = exchangeAuthCodeForAccessToken(authCode);
        try {
            accessTokenObject = new AccessToken(accessTokenString, signingKeyResolver);
        } catch (Exception ex) {
            LOGGER.error("Unable to validate access token: {}", ex.getMessage());
            throw forbiddenError("Unable to validate access token");
        }

        // extract the subject from the id token and verify it matches

        if (!validateTokenSubject(accessTokenObject, confirmation.getDomain(), userName)) {
            throw forbiddenError("Subject token does not match requested user name");
        }

        // verify that the audience in the token matches the configured audience

        if (!StringUtil.isEmpty(audience) && !audience.equals(accessTokenObject.getAudience())) {
            LOGGER.error("Audience mismatch: token-audience={} vs. configured-audience={}",
                    accessTokenObject.getAudience(), audience);
            throw forbiddenError("Token audience mismatch");
        }

        // our validation is done, return the confirmation object

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        throw forbiddenError("User X.509 Certificates cannot be refreshed");
    }

    boolean validateTokenSubject(final AccessToken accessToken, final String domainName, final String userName) {

        // when validing the token identity, we need to consider two cases:
        // 1. the token subject is the same as the requested user name without the domain prefix
        // 2. the token subject is the same as the requested user name with the domain prefix

        final String fullName = domainName + AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER_CHAR + userName;

        // first, verify that the subject in the token matches the requested user name

        final String tokenSubject = accessToken.getSubject();
        if (userName.equals(tokenSubject) || fullName.equals(tokenSubject)) {
            return true;
        }

        // if the user name claim is configured, verify that the claim value 
        // in the token matches the requested user name

        String tokenUserName = null;
        if (!StringUtil.isEmpty(userNameClaim)) {
            tokenUserName = (String) accessToken.getClaim(userNameClaim);
            if (userName.equals(tokenUserName) || fullName.equals(tokenUserName)) {
                return true;
            }
        }

        LOGGER.error("Subject mismatch: token-subject={}/user-name={} vs. requested-user={}",
            accessToken.getSubject(), tokenUserName, fullName);
        return false;
    }

    String extractAuthCode(final String attestationData) {

        // the attestation data could be:
        // 1. a query string from the OAuth2 callback (code=...&state=...)
        // 2. just the raw authorization code

        if (attestationData.contains(CODE_PREFIX)) {
            String[] params = attestationData.split("&");
            for (String param : params) {
                if (param.startsWith(CODE_PREFIX)) {
                    return param.substring(CODE_PREFIX.length());
                }
            }
            return null;
        }

        return attestationData;
    }

    String exchangeAuthCodeForAccessToken(final String authCode) throws ProviderResourceException {

        final String requestBody = "grant_type=authorization_code"
                + "&code=" + URLEncoder.encode(authCode, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + (StringUtil.isEmpty(clientSecret) ? "" :
                    "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8));

        AccessTokenResponse accessTokenResponse = postTokenRequest(requestBody);

        final String accessToken = accessTokenResponse.getAccess_token();
        if (StringUtil.isEmpty(accessToken)) {
            throw forbiddenError("IdP token response does not contain an access token");
        }

        return accessToken;
    }

    AccessTokenResponse postTokenRequest(final String requestBody) throws ProviderResourceException {

        HttpURLConnection conn = null;
        try {
            conn = createTokenEndpointConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(requestBody.getBytes(StandardCharsets.UTF_8));
            }
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                LOGGER.error("IdP token endpoint returned error: responseMessage={}", conn.getResponseMessage());
                throw forbiddenError("IdP token endpoint returned error: " + responseCode);
            }

            return jsonMapper.readValue(conn.getInputStream(), AccessTokenResponse.class);

        } catch (ProviderResourceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw forbiddenError("Unable to exchange auth code with IdP: " + ex.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    HttpURLConnection createTokenEndpointConnection() throws IOException {
        return (HttpURLConnection) new URL(tokenEndpoint).openConnection();
    }

    private ProviderResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ProviderResourceException(ProviderResourceException.FORBIDDEN, message);
    }
}

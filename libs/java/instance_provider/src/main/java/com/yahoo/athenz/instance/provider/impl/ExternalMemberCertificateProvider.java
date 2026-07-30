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
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class ExternalMemberCertificateProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalMemberCertificateProvider.class);

    static final String EXT_MEMBER_CERT_PROP_CONFIG_ENDPOINT =
            "athenz.zts.external_member_cert.idp_config_endpoint";
    static final String EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT =
            "athenz.zts.external_member_cert.idp_token_endpoint";
    static final String EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT =
            "athenz.zts.external_member_cert.idp_jwks_endpoint";
    static final String EXT_MEMBER_CERT_PROP_CLIENT_ID =
            "athenz.zts.external_member_cert.idp_client_id";
    static final String EXT_MEMBER_CERT_PROP_REDIRECT_URI =
            "athenz.zts.external_member_cert.idp_redirect_uri";
    static final String EXT_MEMBER_CERT_PROP_AUDIENCE =
            "athenz.zts.external_member_cert.idp_audience";
    static final String EXT_MEMBER_CERT_PROP_CONNECT_TIMEOUT =
            "athenz.zts.external_member_cert.connect_timeout";
    static final String EXT_MEMBER_CERT_PROP_READ_TIMEOUT =
            "athenz.zts.external_member_cert.read_timeout";
    static final String EXT_MEMBER_CERT_PROP_MEMBER_NAME_CLAIM =
            "athenz.zts.external_member_cert.member_name_claim";

    static final String EXT_MEMBER_CERT_PROP_CLIENT_SECRET_APP =
            "athenz.zts.external_member_cert.idp_client_secret_app";
    static final String EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYGROUP =
            "athenz.zts.external_member_cert.idp_client_secret_keygroup";
    static final String EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYNAME =
            "athenz.zts.external_member_cert.idp_client_secret_keyname";

    static final String CODE_PREFIX = "code=";
    static final String CODE_VERIFIER_PREFIX = "code_verifier=";

    static final String DEFAULT_REDIRECT_URI = "http://127.0.0.1:9213/oauth2/callback";

    String tokenEndpoint;
    String clientId;
    String clientSecret;
    String redirectUri;
    String memberNameClaim;
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
        final String configEndpoint = System.getProperty(EXT_MEMBER_CERT_PROP_CONFIG_ENDPOINT);
        if (!StringUtil.isEmpty(configEndpoint)) {
            JwtsHelper helper = new JwtsHelper();
            OpenIdConfiguration openIdConfig = helper.extractOpenIdConfiguration(configEndpoint, sslContext, null);
            if (openIdConfig != null) {
                tokenEndpoint = openIdConfig.getTokenEndpoint();
                jwksEndpoint = openIdConfig.getJwksUri();
            }
        }

        if (StringUtil.isEmpty(tokenEndpoint)) {
            tokenEndpoint = System.getProperty(EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT);
            if (StringUtil.isEmpty(tokenEndpoint)) {
                throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                        "External member IdP token endpoint not configured");
            }
        }

        if (!tokenEndpoint.toLowerCase().startsWith("https://")) {
            throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                    "External member IdP token endpoint must be an https url");
        }

        if (StringUtil.isEmpty(jwksEndpoint)) {
            jwksEndpoint = System.getProperty(EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT);
            if (StringUtil.isEmpty(jwksEndpoint)) {
                throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                        "External member IdP jwks endpoint not configured");
            }
        }

        if (!jwksEndpoint.toLowerCase().startsWith("https://")) {
            throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                    "External member IdP jwks endpoint must be an https url");
        }

        signingKeyResolver = new JwtsSigningKeyResolver(jwksEndpoint, null);

        clientId = System.getProperty(EXT_MEMBER_CERT_PROP_CLIENT_ID);
        if (StringUtil.isEmpty(clientId)) {
            throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                    "External member IdP client id not configured");
        }

        clientSecret = getClientSecret();
        redirectUri = System.getProperty(EXT_MEMBER_CERT_PROP_REDIRECT_URI, DEFAULT_REDIRECT_URI);

        audience = System.getProperty(EXT_MEMBER_CERT_PROP_AUDIENCE);
        if (StringUtil.isEmpty(audience)) {
            throw new ProviderResourceException(ProviderResourceException.INTERNAL_SERVER_ERROR,
                    "External member IdP audience not configured");
        }

        connectTimeout = Integer.parseInt(System.getProperty(EXT_MEMBER_CERT_PROP_CONNECT_TIMEOUT, "10000"));
        readTimeout = Integer.parseInt(System.getProperty(EXT_MEMBER_CERT_PROP_READ_TIMEOUT, "15000"));

        memberNameClaim = System.getProperty(EXT_MEMBER_CERT_PROP_MEMBER_NAME_CLAIM);
    }

    String getClientSecret() {

        if (privateKeyStore == null) {
            return "";
        }

        final String appName = System.getProperty(EXT_MEMBER_CERT_PROP_CLIENT_SECRET_APP, "");
        final String keygroupName = System.getProperty(EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYGROUP, "");
        final String keyName = System.getProperty(EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYNAME, "");

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
            throw forbiddenError("External member attestation data not provided");
        }

        final String memberName = confirmation.getService();
        if (StringUtil.isEmpty(memberName)) {
            throw forbiddenError("External member name not provided in confirmation");
        }

        AccessToken accessTokenObject;
        final String accessTokenString = exchangeAuthCodeForAccessToken(attestationData);
        try {
            accessTokenObject = new AccessToken(accessTokenString, signingKeyResolver);
        } catch (Exception ex) {
            LOGGER.error("Unable to validate external member access token: {}", ex.getMessage());
            throw forbiddenError("Unable to validate external member access token");
        }

        if (!validateTokenSubject(accessTokenObject, memberName)) {
            throw forbiddenError("Subject token does not match requested external member name");
        }

        if (!audience.equals(accessTokenObject.getAudience())) {
            LOGGER.error("External member audience mismatch: token-audience={} vs. configured-audience={}",
                    accessTokenObject.getAudience(), audience);
            throw forbiddenError("External member token audience mismatch");
        }

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        throw forbiddenError("External member X.509 Certificates cannot be refreshed");
    }

    boolean validateTokenSubject(final AccessToken accessToken, final String memberName) {

        final String tokenSubject = accessToken.getSubject();
        if (memberName.equals(tokenSubject)) {
            return true;
        }

        String tokenMemberName = null;
        if (!StringUtil.isEmpty(memberNameClaim)) {
            tokenMemberName = (String) accessToken.getClaim(memberNameClaim);
            if (memberName.equals(tokenMemberName)) {
                return true;
            }
        }

        LOGGER.error("External member subject mismatch: token-subject={}/member-name={} vs. requested-member={}",
                tokenSubject, tokenMemberName, memberName);
        return false;
    }

    String generateAccessTokenRequestBody(final String attestationData) throws ProviderResourceException {

        String code = null;
        String codeVerifier = null;

        String requestBody = "grant_type=authorization_code"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        String[] params = attestationData.split("&");
        for (String param : params) {
            if (param.startsWith(CODE_PREFIX)) {
                code = URLDecoder.decode(param.substring(CODE_PREFIX.length()), StandardCharsets.UTF_8);
            } else if (param.startsWith(CODE_VERIFIER_PREFIX)) {
                codeVerifier = URLDecoder.decode(param.substring(CODE_VERIFIER_PREFIX.length()), StandardCharsets.UTF_8);
            }
        }

        if (StringUtil.isEmpty(code)) {
            throw forbiddenError("Code not provided in external member attestation data");
        }

        if (StringUtil.isEmpty(clientSecret)) {
            if (StringUtil.isEmpty(codeVerifier)) {
                throw forbiddenError("External member PKCE is required but code verifier not provided");
            }
        } else {
            requestBody += "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        }

        requestBody += "&" + CODE_PREFIX + URLEncoder.encode(code, StandardCharsets.UTF_8);
        if (!StringUtil.isEmpty(codeVerifier)) {
            requestBody += "&" + CODE_VERIFIER_PREFIX + URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8);
        }

        return requestBody;
    }

    String exchangeAuthCodeForAccessToken(final String attestationData) throws ProviderResourceException {

        AccessTokenResponse accessTokenResponse = postTokenRequest(generateAccessTokenRequestBody(attestationData));

        final String accessToken = accessTokenResponse.getAccess_token();
        if (StringUtil.isEmpty(accessToken)) {
            throw forbiddenError("External member IdP token response does not contain an access token");
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
                LOGGER.error("External member IdP token endpoint returned error: responseMessage={}",
                        conn.getResponseMessage());
                throw forbiddenError("External member IdP token endpoint returned error: " + responseCode);
            }

            return jsonMapper.readValue(conn.getInputStream(), AccessTokenResponse.class);

        } catch (ProviderResourceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw forbiddenError("Unable to exchange external member auth code with IdP: " + ex.getMessage());
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

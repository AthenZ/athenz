/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.auth.oauth;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.CertificateIdentity;
import com.yahoo.athenz.auth.impl.CertificateIdentityException;
import com.yahoo.athenz.auth.impl.CertificateIdentityParser;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.oauth.parser.OAuthJwtAccessTokenParser;
import com.yahoo.athenz.auth.oauth.parser.OAuthJwtAccessTokenParserFactory;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import com.yahoo.athenz.auth.oauth.util.JwtAuthorityUtils;
import com.yahoo.athenz.auth.oauth.validator.DefaultOAuthJwtAccessTokenValidator;
import com.yahoo.athenz.auth.oauth.validator.OAuthJwtAccessTokenValidator;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authority to authenticate OAuth2 certificate bound access token
 */
public class CertificateJwtAccessTokenAuthority implements Authority, AuthorityKeyStore, KeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateJwtAccessTokenAuthority.class);

    @Override
    public void setKeyStore(KeyStore keyStore) {
        // called after initialize() during server init., will load keys from DB
        // used by the JWT parser to resolve the JWT public key
        this.keyStore = keyStore;
    }

    @Override
    public String getPublicKey(String domain, String service, String keyId) {
        return this.keyStore.getPublicKey(domain, service, keyId);
    }

    @Override
    public CredSource getCredSource() {
        return CredSource.REQUEST;
    }

    private String authenticateChallenge = "Bearer realm=\"athenz\"";

    @Override
    public String getAuthenticateChallenge() {
        // https://tools.ietf.org/html/rfc6750.html#page-9
        return this.authenticateChallenge;
    }

    // private String userDomain = "user";
    @Override
    public String getDomain() {
        // return this.userDomain;
        return null; // to support create principal for different domains
    }

    @Override
    public String getHeader() {
        // https://tools.ietf.org/html/rfc6750.html#page-5
        return JwtAuthorityConsts.AUTH_HEADER;
    }

    @Override
    public Principal authenticate(String credentials, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        // disable authenticate using header mode
        return null;
    }

    // --------------------- until functions ---------------------
    private void reportError(final String message, StringBuilder errMsg) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(message);
        }
        if (errMsg != null) {
            errMsg.append(message);
        }
    }
    private void processClientIdsMap(String clientIdsMapPath, Map<String, Set<String>> clientIdsMap, Map<String, String> authorizedServiceMap) {
        if (clientIdsMapPath == null || clientIdsMapPath.isEmpty()) {
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(clientIdsMapPath))) {
            String line = null;
            while ((line = br.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                final String mapEntry = line.trim();
                String[] comps = mapEntry.split(JwtAuthorityConsts.CLIENT_ID_FIELD_DELIMITER);
                if (comps.length != 3) {
                    LOG.error("Skipping invalid client id entry {}", mapEntry);
                    continue;
                }

                // format: client-id-1,client-id-2:ui-principal:authorized-service
                clientIdsMap.put(comps[1], JwtAuthorityUtils.csvToSet(comps[0], JwtAuthorityConsts.CLIENT_ID_DELIMITER));
                authorizedServiceMap.put(comps[1], comps[2]);
            }
        } catch (Exception e) {
            LOG.error("Unable to process client id list: {}", e.getMessage());
        }
    }
    private String clientCertPrincipalToAuthorizedService(String clientCertPrincipal) {
        return this.authorizedServiceMap.getOrDefault(clientCertPrincipal, clientCertPrincipal);
    }

    // --------------------- actual logic ---------------------
    private KeyStore keyStore = null;
    private CertificateIdentityParser certificateIdentityParser = null;
    private OAuthJwtAccessTokenParser parser = null;
    private OAuthJwtAccessTokenValidator validator = null;
    Map<String, String> authorizedServiceMap = null;
    private boolean shouldVerifyCertThumbprint = true;

    @Override
    public void initialize() {
        String authnChallengeRealm = JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_AUTHN_CHALLENGE_REALM, "https://athenz.io");
        this.authenticateChallenge = String.format("Bearer realm=\"%s\"", authnChallengeRealm);

        // no need to load user domain
        // this.userDomain = userDomain;

        // certificate parser
        boolean excludeRoleCertificates = Boolean.valueOf(JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_CERT_EXCLUDE_ROLE_CERTIFICATES, "false"));
        Set<String> excludedPrincipals = JwtAuthorityUtils.csvToSet(JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_CERT_EXCLUDED_PRINCIPALS, ""), JwtAuthorityConsts.CSV_DELIMITER);
        this.certificateIdentityParser = new CertificateIdentityParser(excludedPrincipals, excludeRoleCertificates);

        // JWT parser
        String jwtParserFactoryClass = JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_PARSER_FACTORY_CLASS, "com.yahoo.athenz.auth.oauth.parser.DefaultOAuthJwtAccessTokenParserFactory");
        try {
            OAuthJwtAccessTokenParserFactory jwtParserFactory = (OAuthJwtAccessTokenParserFactory) Class.forName(jwtParserFactoryClass).newInstance();
            this.parser = jwtParserFactory.create(this);
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOG.error("Invalid OAuthJwtAccessTokenParserFactory class: " + jwtParserFactoryClass + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid JWT parser class", e);
        }

        // JWT validator client ID mapping
        String clientIdsMapPath = JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_CLIENT_ID_MAP_PATH, "");
        Map<String, Set<String>> clientIdsMap = new HashMap<>();
        Map<String, String> authorizedServiceMap = new HashMap<>();
        this.processClientIdsMap(clientIdsMapPath, clientIdsMap, authorizedServiceMap);
        this.authorizedServiceMap = authorizedServiceMap;
        // JWT validator controls
        this.shouldVerifyCertThumbprint = Boolean.valueOf(JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_VERIFY_CERT_THUMBPRINT, "true"));
        // JWT validator values
        String trustedIssuer = JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_CLAIM_ISS, "https://athenz.io");
        Set<String> requiredAudiences = JwtAuthorityUtils.csvToSet(JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_CLAIM_AUD, "https://zms.athenz.io"), JwtAuthorityConsts.CSV_DELIMITER);
        Set<String> requiredScopes = JwtAuthorityUtils.csvToSet(JwtAuthorityUtils.getProperty(JwtAuthorityConsts.JA_PROP_CLAIM_SCOPE, "sys.auth:role.admin"), OAuthJwtAccessToken.SCOPE_DELIMITER);
        // JWT validator
        this.validator = new DefaultOAuthJwtAccessTokenValidator(trustedIssuer, requiredAudiences, requiredScopes, clientIdsMap);
    }

    @Override
    public Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        // extract credentials from request
        String jwsString = JwtAuthorityUtils.extractHeaderToken(request);

        // skip when no credentials provided
        if (jwsString == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CertificateJwtAccessTokenAuthority:authenticate: no credentials, skip...");
            }
            return null;
        }

        // parse certificate
        CertificateIdentity certificateIdentity = null;
        try {
            certificateIdentity = this.certificateIdentityParser.parse(request);
        } catch (CertificateIdentityException e) {
            this.reportError("CertificateJwtAccessTokenAuthority:authenticate: invalid certificate: " + e.getMessage(), errMsg);
            return null;
        }
        X509Certificate clientCert = certificateIdentity.getX509Certificate();
        String clientCertPrincipal = certificateIdentity.getPrincipalName();

        // parse JWT
        OAuthJwtAccessToken at = null;
        try {
            at = this.parser.parse(jwsString);
        } catch (OAuthJwtAccessTokenException e) {
            this.reportError("CertificateJwtAccessTokenAuthority:authenticate: invalid JWT: " + e.getMessage(), errMsg);
            return null;
        }

        // validate JWT
        try {
            this.validator.validate(at);
            this.validator.validateClientId(at, clientCertPrincipal);

            if (this.shouldVerifyCertThumbprint) {
                String clientCertThumbprint = this.validator.getX509CertificateThumbprint(clientCert);
                this.validator.validateCertificateBinding(at, clientCertThumbprint);
            }
        } catch (CertificateEncodingException | CryptoException | OAuthJwtAccessTokenException e) {
            this.reportError("CertificateJwtAccessTokenAuthority:authenticate: invalid JWT: " + e.getMessage(), errMsg);
            return null;
        }

        // create principal
        String[] ds = AthenzUtils.splitPrincipalName(at.getSubject());
        if (ds == null) {
            errMsg.append("CertificateJwtAccessTokenAuthority:authenticate: sub is not a valid service identity: got=").append(at.getSubject());
            return null;
        }
        String domain = ds[0];
        String service = ds[1];

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(domain, service, jwsString, at.getIssuedAt(), this);
        principal.setUnsignedCreds(at.toString());
        principal.setX509Certificate(clientCert);
        // principal.setRoles(at.getScopes());
        principal.setApplicationId(clientCertPrincipal);
        principal.setAuthorizedService(this.clientCertPrincipalToAuthorizedService(clientCertPrincipal));

        if (LOG.isDebugEnabled()) {
            LOG.debug("CertificateJwtAccessTokenAuthority.authenticate: client certificate name=" + clientCertPrincipal);
            LOG.debug("CertificateJwtAccessTokenAuthority.authenticate: valid user=" + principal.toString());
            LOG.debug("CertificateJwtAccessTokenAuthority.authenticate: unsignedCredentials=" + principal.getUnsignedCredentials());
            LOG.debug("CertificateJwtAccessTokenAuthority.authenticate: credentials=" + principal.getCredentials());
        }
        return principal;
    }

}

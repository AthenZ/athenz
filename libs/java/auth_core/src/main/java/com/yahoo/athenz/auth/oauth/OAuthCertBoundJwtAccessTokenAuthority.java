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
package com.yahoo.athenz.auth.oauth;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
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
import com.yahoo.athenz.auth.oauth.util.OAuthAuthorityUtils;
import com.yahoo.athenz.auth.oauth.validator.DefaultOAuthJwtAccessTokenValidator;
import com.yahoo.athenz.auth.oauth.validator.OAuthJwtAccessTokenValidator;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authority to authenticate OAuth2 certificate bound access token
 */

public class OAuthCertBoundJwtAccessTokenAuthority implements Authority, AuthorityKeyStore, KeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthCertBoundJwtAccessTokenAuthority.class);

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

    private String authenticateChallenge = "Bearer realm=\"athenz.io\"";

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
        return OAuthAuthorityConsts.AUTH_HEADER;
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
    /**
     * format: client-id-1,client-id-2:ui-principal:authorized-service, will skip line on error
     * @param authorizedClientIdsPath client IDs mapping file path
     * @param authorizedClientIds     client IDs mapping entry will be added
     * @param authorizedServices      authorized service mapping entry will be added
     */
    private void processAuthorizedClientIds(String authorizedClientIdsPath, Map<String, Set<String>> authorizedClientIds, Map<String, String> authorizedServices) {
        if (authorizedClientIdsPath == null || authorizedClientIdsPath.isEmpty()) {
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(authorizedClientIdsPath))) {
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (line.isEmpty()) {
                    continue;
                }

                final String mapEntry = line.trim();
                boolean isInvalid = false;
                String[] comps = mapEntry.split(OAuthAuthorityConsts.CLIENT_ID_FIELD_DELIMITER);
                if (comps.length != 3) {
                    LOG.error("Skipping invalid client id entry {}", mapEntry);
                    isInvalid = true;
                }
                for (String comp: comps) {
                    if (comp.isEmpty()) {
                        LOG.error("Skipping invalid client id entry {}", mapEntry);
                        isInvalid = true;
                        break;
                    }
                }
                if (isInvalid) {
                    continue;
                }

                Set<String> clientIds = OAuthAuthorityUtils.csvToSet(comps[0], OAuthAuthorityConsts.CLIENT_ID_DELIMITER);
                if (clientIds == null || clientIds.contains("")) {
                    LOG.error("Skipping invalid client id entry {}", mapEntry);
                    continue;
                }
                authorizedClientIds.put(comps[1], clientIds);
                authorizedServices.put(comps[1], comps[2]);
            }
        } catch (Exception e) {
            LOG.error("Unable to process client id list: {}", e.getMessage());
        }
    }

    // --------------------- actual logic ---------------------
    private KeyStore keyStore = null;
    private CertificateIdentityParser certificateIdentityParser = null;
    private OAuthJwtAccessTokenParser parser = null;
    private OAuthJwtAccessTokenValidator validator = null;
    Map<String, String> authorizedServices = null;
    private boolean shouldVerifyCertThumbprint = true;

    @Override
    public void initialize() {
        String authnChallengeRealm = OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_AUTHN_CHALLENGE_REALM, "https://athenz.io");
        this.authenticateChallenge = String.format("Bearer realm=\"%s\"", authnChallengeRealm);

        // no need to load user domain
        // this.userDomain = userDomain;

        // certificate parser
        boolean excludeRoleCertificates = Boolean.parseBoolean(OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_CERT_EXCLUDE_ROLE_CERTIFICATES, "false"));
        Set<String> excludedPrincipals = OAuthAuthorityUtils.csvToSet(OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_CERT_EXCLUDED_PRINCIPALS, ""), OAuthAuthorityConsts.CSV_DELIMITER);
        this.certificateIdentityParser = new CertificateIdentityParser(excludedPrincipals, excludeRoleCertificates);

        // JWT parser
        String jwtParserFactoryClass = OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_PARSER_FACTORY_CLASS, "com.yahoo.athenz.auth.oauth.parser.DefaultOAuthJwtAccessTokenParserFactory");
        try {
            OAuthJwtAccessTokenParserFactory jwtParserFactory = (OAuthJwtAccessTokenParserFactory)
                    Class.forName(jwtParserFactoryClass).getDeclaredConstructor().newInstance();
            this.parser = jwtParserFactory.create(this);
        } catch (Exception ex) {
            LOG.error("Invalid OAuthJwtAccessTokenParserFactory class: {}", jwtParserFactoryClass, ex);
            throw new IllegalArgumentException("Invalid JWT parser class", ex);
        }

        // JWT validator controls
        this.shouldVerifyCertThumbprint = Boolean.parseBoolean(OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_VERIFY_CERT_THUMBPRINT, "true"));
        // JWT validator client ID mapping
        String authorizedClientIdsPath = OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_AUTHORIZED_CLIENT_IDS_PATH, "");
        Map<String, Set<String>> authorizedClientIds = new HashMap<>();
        Map<String, String> authorizedServices = new HashMap<>();
        this.processAuthorizedClientIds(authorizedClientIdsPath, authorizedClientIds, authorizedServices);
        this.authorizedServices = authorizedServices;
        // JWT validator values
        String trustedIssuer = OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_CLAIM_ISS, "https://athenz.io");
        Set<String> requiredAudiences = OAuthAuthorityUtils.csvToSet(OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_CLAIM_AUD, "https://zms.athenz.io"), OAuthAuthorityConsts.CSV_DELIMITER);
        Set<String> requiredScopes = OAuthAuthorityUtils.csvToSet(OAuthAuthorityUtils.getProperty(OAuthAuthorityConsts.JA_PROP_CLAIM_SCOPE, "sys.auth:role.admin"), OAuthJwtAccessToken.SCOPE_DELIMITER);
        // JWT validator
        this.validator = new DefaultOAuthJwtAccessTokenValidator(trustedIssuer, requiredAudiences, requiredScopes, authorizedClientIds);
    }

    /**
     * Process the authenticate request based on http request object.
     * Skip if access token not exists or cannot be extracted.
     * Fail if it is not mTLS.
     * @param request http servlet request
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the certificate, or null in case of failure.
     */
    @Override
    public Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        // extract credentials from request
        String jwsString = OAuthAuthorityUtils.extractHeaderToken(request);

        // skip when no credentials provided
        if (jwsString == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuthCertBoundJwtAccessTokenAuthority:authenticate: no credentials, skip...");
            }
            return null;
        }

        // parse certificate
        CertificateIdentity certificateIdentity;
        try {
            certificateIdentity = this.certificateIdentityParser.parse(request);
        } catch (CertificateIdentityException e) {
            this.reportError("OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid certificate: " + e.getMessage(), errMsg);
            return null;
        }
        X509Certificate clientCert = certificateIdentity.getX509Certificate();
        String clientCertPrincipal = certificateIdentity.getPrincipalName();

        // parse JWT
        OAuthJwtAccessToken at;
        try {
            at = this.parser.parse(jwsString);
        } catch (OAuthJwtAccessTokenException e) {
            this.reportError("OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: " + e.getMessage(), errMsg);
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
            this.reportError("OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: " + e.getMessage(), errMsg);
            return null;
        }

        // create principal
        String[] ds = AthenzUtils.splitPrincipalName(at.getSubject());
        if (ds == null) {
            errMsg.append("OAuthCertBoundJwtAccessTokenAuthority:authenticate: sub is not a valid service identity: got=").append(at.getSubject());
            return null;
        }
        String domain = ds[0];
        String service = ds[1];

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(domain, service, jwsString, at.getIssuedAt(), this);
        principal.setUnsignedCreds(at.toString());
        principal.setX509Certificate(clientCert);
        principal.setApplicationId(clientCertPrincipal);
        principal.setAuthorizedService(this.authorizedServices.getOrDefault(clientCertPrincipal, clientCertPrincipal));

        if (LOG.isDebugEnabled()) {
            LOG.debug("OAuthCertBoundJwtAccessTokenAuthority.authenticate: client certificate name={}", clientCertPrincipal);
            LOG.debug("OAuthCertBoundJwtAccessTokenAuthority.authenticate: valid user={}", principal);
            LOG.debug("OAuthCertBoundJwtAccessTokenAuthority.authenticate: unsignedCredentials={}", principal.getUnsignedCredentials());
            LOG.debug("OAuthCertBoundJwtAccessTokenAuthority.authenticate: credentials={}", principal.getCredentials());
        }
        return principal;
    }

}

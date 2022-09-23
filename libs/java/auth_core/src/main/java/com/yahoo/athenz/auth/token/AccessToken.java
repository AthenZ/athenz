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
package com.yahoo.athenz.auth.token;

import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

public class AccessToken extends OAuth2Token {

    public static final String HDR_TOKEN_TYPE = "typ";
    public static final String HDR_TOKEN_JWT = "at+jwt";

    public static final String CLAIM_SCOPE = "scp";
    public static final String CLAIM_SCOPE_STD = "scope";
    public static final String CLAIM_UID = "uid";
    public static final String CLAIM_CLIENT_ID = "client_id";
    public static final String CLAIM_CONFIRM = "cnf";
    public static final String CLAIM_PROXY = "proxy";
    public static final String CLAIM_AUTHZ_DETAILS = "authorization_details";

    public static final String CLAIM_CONFIRM_X509_HASH = "x5t#S256";
    public static final String CLAIM_CONFIRM_PROXY_SPIFFE = "proxy-principals#spiffe";

    private static final Logger LOG = LoggerFactory.getLogger(AccessToken.class);

    // by default we're going to allow the access token to be
    // validated by the identity/spiffe uris and not carry
    // out strict cert hash based validation only
    private static long ACCESS_TOKEN_CERT_OFFSET = -1;

    // default no check on access token proxy principals
    private static Set<String> ACCESS_TOKEN_PROXY_PRINCIPALS = null;

    private String clientId;
    private String userId;
    private String proxyPrincipal;
    private String authorizationDetails;
    private String scopeStd;
    private List<String> scope;
    private LinkedHashMap<String, Object> confirm;

    /**
     * Creates an empty access token
     */
    public AccessToken() {
        super();
    }

    /**
     * Parses and validates the given token based on the keyResolver
     *
     * @param token       access token
     * @param keyResolver JwtsSigningKeyResolver key resolver providing
     *                    the public key for token signature validation
     */
    public AccessToken(final String token, JwtsSigningKeyResolver keyResolver) {
        super(token, keyResolver);
        setAccessTokenFields();
    }

    /**
     * Parses and validates the given token based on the given public key
     *
     * @param token     access token
     * @param publicKey the public key for token signature validation
     */
    public AccessToken(final String token, PublicKey publicKey) {
        super(token, publicKey);
        setAccessTokenFields();
    }

    /**
     * Parses and validates the given token based on the keyResolver
     * Once parsed, it verified that the token contains the x.509
     * certificate hash based on given certificate: supporting
     * mTLS bound access tokens.
     * With mTLS bound access tokens it's possible that the application
     * fetched and cached the access token which includes the x.509 cert
     * hash. However, after that, the cert has been refreshed - so it
     * has a new hash but the same principal/subject. In this case we
     * want to provide a small offset period where we'll check that
     * the certificate creation time is after the access token timestamp
     * and if that's the case allow the access token to be validated
     * as long as the principal/subject matches what's in the token.
     * The offset is by default 3600secs before (since we always issue
     * certs with start time of now - 3600secs) and 3600 secs after. The
     * second value is configurable with setAccessTokenCertOffset api
     * method.
     *
     * @param token       access token
     * @param keyResolver JwtsSigningKeyResolver key resolver providing
     *                    the public key for token signature validation
     * @param x509Cert    x.509 certificate to validate confirmation claim
     */
    public AccessToken(final String token, JwtsSigningKeyResolver keyResolver,
                       X509Certificate x509Cert) {
        this(token, keyResolver, x509Cert, null);
    }

    /**
     * Parses and validates the given token based on the keyResolver
     * Once parsed, it verified that the token contains the x.509
     * certificate hash based on given certificate: supporting
     * mTLS bound access tokens.
     * With mTLS bound access tokens it's possible that the application
     * fetched and cached the access token which includes the x.509 cert
     * hash. However, after that, the cert has been refreshed - so it
     * has a new hash but the same principal/subject. In this case we
     * want to provide a small offset period where we'll check that
     * the certificate creation time is after the access token timestamp
     * and if that's the case allow the access token to be validated
     * as long as the principal/subject matches what's in the token.
     * The offset is by default 3600secs before (since we always issue
     * certs with start time of now - 3600secs) and 3600 secs after. The
     * second value is configurable with setAccessTokenCertOffset api
     * method.
     * If the request is going through a proxy server which handles
     * tls termination then the certificate hash will no longer match.
     * In this case, the proxy is required to calculate and forward
     * the certificate hash in a header that the client can extract
     * and ask the library to validate based on that value. Additionally,
     * the client can configure what service identity names it will
     * accept proxy requests from for further security checks.
     *
     * @param token        access token
     * @param keyResolver  JwtsSigningKeyResolver key resolver providing
     *                     the public key for token signature validation
     * @param x509Cert     x.509 certificate to validate confirmation claim
     * @param x509CertHash x.509 certificate hash for proxy use case
     */
    public AccessToken(final String token, JwtsSigningKeyResolver keyResolver,
                       X509Certificate x509Cert, final String x509CertHash) {
        super(token, keyResolver);
        setAccessTokenFields();
        if (!confirmMTLSBoundToken(x509Cert, x509CertHash)) {
            LOG.error("AccessToken: X.509 Certificate Confirmation failure");
            throw new CryptoException(CryptoException.CERT_HASH_MISMATCH, "X.509 Certificate Confirmation failure");
        }
    }

    /**
     * With mTLS bound access tokens it's possible that the application
     * fetched and cached the access token which includes the x.509 cert
     * hash. However, after that, the cert has been refreshed - so it
     * has a new hash but the same principal/subject. In this case we
     * want to provide a small offset period where we'll check that
     * the certificate creation time is after the access token timestamp
     * and if that's the case allow the access token to be validated
     * as long as the principal/subject matches what's in the token.
     * The offset is by default 3600secs before (since we always issue
     * certs with start time of now - 3600secs) and 3600 secs after.
     * If the value is 0, then no offset is allowed. If the value is -1,
     * then we skip the offset check and only require that the client
     * certificate principal matches to the access token client id
     *
     * @param offset number of seconds to allow access token validation
     *               based on principal/subject name
     */
    public static void setAccessTokenCertOffset(long offset) {
        ACCESS_TOKEN_CERT_OFFSET = offset;
    }

    /**
     * If the request is going through a proxy server which handles
     * tls termination then the certificate hash will no longer match.
     * In this case, the proxy is required to calculate and forward
     * the certificate hash in a header that the client can extract
     * and ask the library to validate based on that value. Additionally,
     * the client can configure what service identity names it will
     * accept proxy requests from for further security checks.
     *
     * @param proxyPrincipals set of certificate principals that are allowed
     *                        to proxy access token requests
     */
    public static void setAccessTokenProxyPrincipals(Set<String> proxyPrincipals) {
        ACCESS_TOKEN_PROXY_PRINCIPALS = proxyPrincipals;
    }

    void setAccessTokenFields() {
        setClientId(body.get(CLAIM_CLIENT_ID, String.class));
        setUserId(body.get(CLAIM_UID, String.class));
        setProxyPrincipal(body.get(CLAIM_PROXY, String.class));
        setScopeStd(body.get(CLAIM_SCOPE_STD, String.class));
        setScope(body.get(CLAIM_SCOPE, List.class));
        setConfirm(body.get(CLAIM_CONFIRM, LinkedHashMap.class));
        setAuthorizationDetails(body.get(CLAIM_AUTHZ_DETAILS, String.class));
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getProxyPrincipal() {
        return proxyPrincipal;
    }

    public void setProxyPrincipal(String proxyPrincipal) {
        this.proxyPrincipal = proxyPrincipal;
    }

    public String getAuthorizationDetails() {
        return authorizationDetails;
    }

    public void setAuthorizationDetails(String authorizationDetails) {
        this.authorizationDetails = authorizationDetails;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
        if (scope != null && !scope.isEmpty() && scopeStd == null) {
            scopeStd = String.join(" ", scope);
        }
    }

    public String getScopeStd() {
        return scopeStd;
    }

    public void setScopeStd(String scopeStd) {
        this.scopeStd = scopeStd;
    }

    public LinkedHashMap<String, Object> getConfirm() {
        return confirm;
    }

    public void setConfirm(LinkedHashMap<String, Object> confirm) {
        this.confirm = confirm;
    }

    public void setConfirmEntry(final String key, final Object value) {
        if (confirm == null) {
            confirm = new LinkedHashMap<>();
        }
        confirm.put(key, value);
    }

    public void setConfirmX509CertHash(X509Certificate cert) {
        setConfirmEntry(CLAIM_CONFIRM_X509_HASH, getX509CertificateHash(cert));
    }

    public void setConfirmProxyPrincipalSpiffeUris(List<String> proxyPrincipalSpiffeUris) {
        setConfirmEntry(CLAIM_CONFIRM_PROXY_SPIFFE, proxyPrincipalSpiffeUris);
    }

    public List<String> getConfirmProxyPrincpalSpiffeUris() {

        List<String> spiffeUris = null;
        try {
            spiffeUris = (List<String>) confirm.get(CLAIM_CONFIRM_PROXY_SPIFFE);
        } catch (Exception ignored) {
        }
        return spiffeUris;
    }

    public boolean confirmMTLSBoundToken(X509Certificate x509Cert, final String x509CertHash) {

        if (x509Cert == null) {
            LOG.error("confirmMTLSBoundToken: null certificate");
            return false;
        }

        // extract our confirmation hash claim

        final String cnfHash = (String) getConfirmEntry(CLAIM_CONFIRM_X509_HASH);
        if (cnfHash == null) {
            LOG.error("confirmMTLSBoundToken: token does not have confirmation entry");
            return false;
        }

        // first we're going to verify our expected
        // x.509 certificate hash

        if (confirmX509CertHash(x509Cert, cnfHash)) {
            return true;
        }

        // extract the certificate service identity for our
        // next set of checks

        final String cn = Crypto.extractX509CertCommonName(x509Cert);
        if (cn == null) {
            LOG.error("confirmMTLSBoundToken: null principal in certificate}");
            return false;
        }

        // check if the certificate principal matches and the
        // creation time for our cert is within our configured
        // offset timeouts

        if (confirmX509CertPrincipal(x509Cert, cn)) {
            return true;
        }

        // check if we have authorization details specified for
        // proxy access thus we can validate based on that

        if (confirmX509CertPrincipalAuthzDetails(x509Cert)) {
            return true;
        }
        // direct comparison of certificate cn and provided hash

        return confirmX509ProxyPrincipal(cn, x509CertHash, cnfHash);
    }

    boolean confirmX509CertPrincipalAuthzDetails(X509Certificate cert) {

        // make sure we have valid proxy principals specified

        List<String> spiffeUris;
        try {
            spiffeUris = (List<String>) confirm.get(CLAIM_CONFIRM_PROXY_SPIFFE);
        } catch (Exception ex) {
            LOG.error("Unable to parse proxy principal claim: {}", ex.getMessage());
            return false;
        }
        if (spiffeUris == null) {
            return false;
        }

        final String certSpiffeUri = Crypto.extractX509CertSpiffeUri(cert);
        for (String spiffeUri : spiffeUris) {
            if (spiffeUri.equalsIgnoreCase(certSpiffeUri)) {
                return true;
            }
        }

        return false;
    }

    boolean confirmX509CertHash(X509Certificate cert, final String cnfHash) {

        final String certHash = getX509CertificateHash(cert);
        return cnfHash.equals(certHash);
    }

    boolean confirmX509ProxyPrincipal(final String cn, final String certHash, final String cnfHash) {

        // if the proxy principal set is not null then the client
        // has specified some value so we'll enforce it (even if
        // the set is empty thus rejecting all requests)

        if (ACCESS_TOKEN_PROXY_PRINCIPALS != null && !ACCESS_TOKEN_PROXY_PRINCIPALS.contains(cn)) {
            LOG.error("confirmX509ProxyPrincipal: unauthorized proxy principal: {}", cn);
            return false;
        }

        return cnfHash.equals(certHash);
    }

    boolean confirmX509CertPrincipal(X509Certificate cert, final String cn) {

        // if our offset is 0 then the additional confirmation
        // check is disabled

        if (ACCESS_TOKEN_CERT_OFFSET == 0) {
            LOG.error("confirmX509CertPrincipal: check disabled");
            return false;
        }

        // our principal cn must be the client in the token

        if (!cn.equals(clientId)) {
            LOG.error("confirmX509CertPrincipal: Principal mismatch {} vs {}", cn, clientId);
            return false;
        }

        // if the access token cert offset is set to -1 then
        // we only need to verify that the certificate principal
        // matches to the token client id which we have already
        // verified thus we'll return success

        if (ACCESS_TOKEN_CERT_OFFSET == -1) {
            return true;
        }

        // now let's verify our offsets. the certificate must
        // be issued before our token issue time. since athenz
        // always issues certs with backdating one hour, we
        // need to take into account that extra hour

        long certIssueTime = Crypto.extractX509CertIssueTime(cert);
        if (certIssueTime < issueTime - 3600) {
            LOG.error("confirmX509CertPrincipal: Certificate: {} issued before token: {}",
                    certIssueTime, issueTime);
            return false;
        }

        // also the certificate must be issued after the configured
        // number of seconds after our token issue time. again,
        // since athenz issues certs with backdating one hour, we
        // need to take into account that extra hour

        if (certIssueTime > issueTime + ACCESS_TOKEN_CERT_OFFSET - 3600) {
            LOG.error("confirmX509CertPrincipal: Certificate: {} past configured offset {} for token: {}",
                    certIssueTime, ACCESS_TOKEN_CERT_OFFSET, issueTime);
            return false;
        }

        return true;
    }

    String getX509CertificateHash(X509Certificate cert) {
        try {
            byte[] encCert = Crypto.sha256(cert.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(encCert);
        } catch (CryptoException | CertificateEncodingException ex) {
            LOG.error("Unable to get X.509 certificate hash", ex);
            return null;
        }
    }

    public Object getConfirmEntry(final String key) {
        return confirm == null ? null : confirm.get(key);
    }

    public String getSignedToken(final PrivateKey key, final String keyId,
                                 final SignatureAlgorithm keyAlg) {

        return Jwts.builder().setSubject(subject)
                .setId(jwtId)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(issueTime)))
                .setExpiration(Date.from(Instant.ofEpochSecond(expiryTime)))
                .setIssuer(issuer)
                .setAudience(audience)
                .claim(CLAIM_AUTH_TIME, authTime)
                .claim(CLAIM_VERSION, version)
                .claim(CLAIM_SCOPE, scope)
                .claim(CLAIM_SCOPE_STD, scopeStd)
                .claim(CLAIM_UID, userId)
                .claim(CLAIM_CLIENT_ID, clientId)
                .claim(CLAIM_CONFIRM, confirm)
                .claim(CLAIM_PROXY, proxyPrincipal)
                .claim(CLAIM_AUTHZ_DETAILS, authorizationDetails)
                .setHeaderParam(HDR_KEY_ID, keyId)
                .setHeaderParam(HDR_TOKEN_TYPE, HDR_TOKEN_JWT)
                .signWith(key, keyAlg)
                .compact();
    }
}

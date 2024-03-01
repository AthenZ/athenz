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
package com.yahoo.athenz.zpe;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.athenz.zpe.pkey.PublicKeyStoreFactory;
import com.yahoo.rdl.Struct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_MILLIS_BETWEEN_ZTS_CALLS;

public class AuthZpeClient {

    private static final Logger LOG = LoggerFactory.getLogger(AuthZpeClient.class);
    
    public static final String ZPE_UPDATER_CLASS = "com.yahoo.athenz.zpe.ZpeUpdater";
    public static final String ZPE_PKEY_CLASS = "com.yahoo.athenz.zpe.pkey.file.FilePublicKeyStoreFactory";

    public static final String ZPE_TOKEN_HDR  = System.getProperty(RoleAuthority.ATHENZ_PROP_ROLE_HEADER, RoleAuthority.HTTP_HEADER);

    public static final String ZTS_PUBLIC_KEY = "zts_public_key";
    public static final String ZMS_PUBLIC_KEY = "zms_public_key";

    public static final String ZTS_PUBLIC_KEY_PREFIX = "zts.public_key.";
    public static final String ZMS_PUBLIC_KEY_PREFIX = "zms.public_key.";
    
    public static final String SYS_AUTH_DOMAIN = "sys.auth";
    public static final String ZTS_SERVICE_NAME = "zts";
    public static final String ZMS_SERVICE_NAME = "zms";
    
    public static final String DEFAULT_DOMAIN = "sys.auth";
    public static final String UNKNOWN_DOMAIN = "unknown";
    public static final String BEARER_TOKEN = "Bearer ";

    private static int allowedOffset = 300;
    private static JwtsSigningKeyResolver accessSignKeyResolver = null;

    private static ZpeClient zpeClt = null;
    private static PublicKeyStore publicKeyStore = null;

    private static final Set<String> X509_ISSUERS_NAMES = new HashSet<>();
    private static final List<List<Rdn>> X509_ISSUERS_RDNS = new ArrayList<>();

    private static int maxTokenCacheSize = 10240;

    public enum AccessCheckStatus {
        ALLOW {
            public String toString() {
                return "Access Check was explicitly allowed";
            }
        },
        DENY {
            public String toString() {
                return "Access Check was explicitly denied";
            }
        },
        DENY_NO_MATCH {
            public String toString() {
                return "Access denied due to no match to any of the assertions defined in domain policy file";
            }
        },
        DENY_ROLETOKEN_EXPIRED {
            public String toString() {
                return "Access denied due to expired Token";
            }
        },
        DENY_ROLETOKEN_INVALID {
            public String toString() {
                return "Access denied due to invalid Token";
            }
        },
        DENY_DOMAIN_MISMATCH {
            public String toString() {
                return "Access denied due to domain mismatch between Resource and Token";
            }
        },
        DENY_DOMAIN_NOT_FOUND {
            public String toString() {
                return "Access denied due to domain not found in library cache";
            }
        },
        DENY_DOMAIN_EXPIRED {
            public String toString() {
                return "Access denied due to expired domain policy file";
            }
        },
        DENY_DOMAIN_EMPTY {
            public String toString() {
                return "Access denied due to no policies in the domain file";
            }
        },
        DENY_INVALID_PARAMETERS {
            public String toString() {
                return "Access denied due to invalid/empty action/resource values";
            }
        },
        DENY_CERT_MISMATCH_ISSUER {
            public String toString() {
                return "Access denied due to certificate mismatch in issuer";
            }
        }, 
        DENY_CERT_MISSING_SUBJECT {
            public String toString() {
                return "Access denied due to missing subject in certificate";
            }
        },
        DENY_CERT_MISSING_DOMAIN {
            public String toString() {
                return "Access denied due to missing domain name in certificate";
            }
        },
        DENY_CERT_MISSING_ROLE_NAME {
            public String toString() {
                return "Access denied due to missing role name in certificate";
            }
        },
        DENY_CERT_HASH_MISMATCH {
            public String toString() {
                return "Access denied due to access token certificate hash mismatch";
            }
        }
    }
    
    static {

        // load public keys

        setPublicKeyStoreFactoryClass(System.getProperty(ZpeConsts.ZPE_PROP_PUBLIC_KEY_CLASS, ZPE_PKEY_CLASS));

        // instantiate implementation classes
        
        setZPEClientClass(System.getProperty(ZpeConsts.ZPE_PROP_CLIENT_IMPL, ZPE_UPDATER_CLASS));

        // set the allowed offset
        
        setTokenAllowedOffset(Integer.parseInt(System.getProperty(ZpeConsts.ZPE_PROP_TOKEN_OFFSET, "300")));

        // set the max role token and access token cache values

        setTokenCacheMaxValue(Integer.parseInt(System.getProperty(ZpeConsts.ZPE_PROP_MAX_TOKEN_CACHE, "10240")));

        // load the x509 issuers
        
        setX509CAIssuers(System.getProperty(ZpeConsts.ZPE_PROP_X509_CA_ISSUERS));

        // initialize the access token signing key resolver

        setAccessTokenSignKeyResolver(null, null);
        
        // save the last zts api call time, and the allowed interval between api calls
        setMillisBetweenZtsCalls(Long.parseLong(System.getProperty(ZPE_PROP_MILLIS_BETWEEN_ZTS_CALLS, Long.toString(30 * 1000 * 60))));
    }

    public static void init() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Init: load the ZPE");
        }
    }

    /**
     * Set the role token allowed offset. this might be necessary
     * if the client and server are not ntp synchronized, and we
     * don't want the server to reject valid role tokens
     * @param offset value in seconds
     */
    public static void setTokenAllowedOffset(int offset) {
        // skip any invalid values
        if (offset > 0) {
            allowedOffset = offset;
        }
    }

    /**
     * Set the limit of role and access tokens that are cached to
     * improve the performance of validating signatures since the
     * tokens must be re-used by clients until they're about to be
     * expired. However, incorrectly configured client might generate
     * a new token for every request and eventually cause the server
     * to run out of memory. Once the limit is reached, the library
     * will no longer cache any tokens until the expiry thread cleans
     * up the expired tokens and the size of the cache is smaller than
     * the configured number. The value of 0 indicates no limit. The
     * default value of cached tokens is 10K. The value can also be
     * configured by using the athenz.zpe.max_token_cache_entries
     * system property.
     * @param maxCacheSize maximum number of tokens cached
     */
    public static void setTokenCacheMaxValue(int maxCacheSize) {
        // skip any invalid values. value 0 indicates no limit
        // while any other positive integer enforces the limit
        if (maxCacheSize > -1) {
            maxTokenCacheSize = maxCacheSize;
        }
    }

    /**
     * Set the list of Athenz CA issuers with their full DNs that
     * ZPE should honor.
     * @param issuers list of Athenz CA issuers separated by |
     */
    public static void setX509CAIssuers(final String issuers) {

        if (issuers == null || issuers.isEmpty()) {
            return;
        }
        
        String[] issuerArray = issuers.split("\\|");
        for (String issuer : issuerArray) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("x509 issuer: {}", issuer);
            }
            X509_ISSUERS_NAMES.add(issuer.replaceAll("\\s+", ""));
            try {
                X509_ISSUERS_RDNS.add(new LdapName(issuer).getRdns());
            } catch (InvalidNameException ex) {
                LOG.error("Invalid issuer: {}, error: {}", issuer, ex.getMessage());
            }
        }
    }
    
    /**
     * Set the com.yahoo.athenz.zpe.pkey.PublicKeyStoreFactory interface
     * implementation class. This factory will be used to create the PublicKeyStore
     * object that the ZPE library will use to retrieve the ZMS and ZTS
     * public keys to validate the policy files and role tokens.
     * @param className com.yahoo.athenz.zpe.pkey.PublicKeyStoreFactory interface
     * implementation class name.
     */
    public static void setPublicKeyStoreFactoryClass(final String className) {
        
        PublicKeyStoreFactory publicKeyStoreFactory;
        try {
            publicKeyStoreFactory = (PublicKeyStoreFactory) Class.forName(className).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
            LOG.error("Invalid PublicKeyStore class: {}, error: {}", className, ex.getMessage());
            throw new RuntimeException(ex);
        }
        publicKeyStore = publicKeyStoreFactory.create();
    }

    /**
     * Set the server connection details for the sign key resolver for access
     * tokens. By default, the resolver is looking for the "athenz.athenz_conf"
     * system property, parses the athenz.conf file and loads any public keys
     * defined. The caller can also specify the server URL and the sslcontext
     * (if required) for the resolver to call and fetch the public keys that
     * will be required to verify the token signatures
     * @param serverUrl server url to fetch json web keys
     * @param sslContext ssl context to be used when establishing connection
     */
    public static void setAccessTokenSignKeyResolver(final String serverUrl, SSLContext sslContext) {
        AuthZpeClient.setAccessTokenSignKeyResolver(serverUrl, sslContext, null);
    }

     /**
     * Set the server connection details for the sign key resolver for access
     * tokens. By default, the resolver is looking for the "athenz.athenz_conf"
     * system property, parses the athenz.conf file and loads any public keys
     * defined. The caller can also specify the server URL, the sslcontext and the proxy URL
     * (if required) for the resolver to call and fetch the public keys that
     * will be required to verify the token signatures
     * @param serverUrl server url to fetch json web keys
     * @param sslContext ssl context to be used when establishing connection
     * @param proxyUrl if a proxy is required, specify the proxy URL
     */
    public static void setAccessTokenSignKeyResolver(final String serverUrl, SSLContext sslContext, final String proxyUrl) {
        accessSignKeyResolver = new JwtsSigningKeyResolver(serverUrl, sslContext, proxyUrl);
    }

    /**
     * Include the specified public key and id in the access token
     * signing resolver
     * @param keyId public key id
     * @param key public key for the given id
     */
    public static void addAccessTokenSignKeyResolverKey(final String keyId, PublicKey key) {
        accessSignKeyResolver.addPublicKey(keyId, key);
    }

    /**
     * Set the ZPE Client implementation class name in case the default
     * ZPE client is not sufficient for some reason.
     * @param className ZPE Client implementation class name
     */
    public static void setZPEClientClass(final String className) {
        
        try {
            zpeClt = (ZpeClient) Class.forName(className).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
            LOG.error("Unable to instantiate zpe class: {}, error: {}",
                    className, ex.getMessage());
            throw new RuntimeException(ex);
        }
        zpeClt.init(null);
    }
    
    public static PublicKey getZtsPublicKey(String keyId) {
        PublicKey publicKey = publicKeyStore.getZtsKey(keyId);
        if (publicKey == null) {
            //  fetch all zts jwk keys and update config and try again
            publicKey = accessSignKeyResolver.getPublicKey(keyId); 
        }
        return publicKey;
    }

    protected static void setMillisBetweenZtsCalls(long millis) {
        accessSignKeyResolver.setMillisBetweenZtsCalls(millis);
    }
    
    public static PublicKey getZmsPublicKey(String keyId) {
        return publicKeyStore.getZmsKey(keyId);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the X509Certificate
     *
     * @param cert - X509 Role Certificate
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(X509Certificate cert, String resource, String action) {
        StringBuilder matchRoleName = new StringBuilder(256);
        return allowAccess(cert, resource, action, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the X509Certificate
     *
     * @param cert - X509 Role Certificate
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(X509Certificate cert, String resource, String action,
            StringBuilder matchRoleName) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("allowAccess: action={} resource={}", action, resource);
        }

        // validate the certificate against CAs if the feature
        // is configured. if the caller does not specify any
        // issuers we're not going to make any checks

        if (!certIssuerMatch(cert)) {
            return AccessCheckStatus.DENY_CERT_MISMATCH_ISSUER;
        }

        String subject = Crypto.extractX509CertCommonName(cert);
        if (subject == null || subject.isEmpty()) {
            LOG.error("allowAccess: missing subject in x.509 certificate");
            return AccessCheckStatus.DENY_CERT_MISSING_SUBJECT;
        }

        int idx = subject.indexOf(AuthorityConsts.ROLE_SEP);
        if (idx == -1) {
            LOG.error("allowAccess: invalid role format in x.509 subject: {}", subject);
            return AccessCheckStatus.DENY_CERT_MISSING_ROLE_NAME;
        }

        String domainName = subject.substring(0, idx);
        if (domainName.isEmpty()) {
            LOG.error("allowAccess: missing domain in x.509 subject: {}", subject);
            return AccessCheckStatus.DENY_CERT_MISSING_DOMAIN;
        }

        String roleName = subject.substring(idx + AuthorityConsts.ROLE_SEP.length());
        if (roleName.isEmpty()) {
            LOG.error("allowAccess: missing role in x.509 subject: {}", subject);
            return AccessCheckStatus.DENY_CERT_MISSING_ROLE_NAME;
        }

        List<String> roles = new ArrayList<>();
        roles.add(roleName);
        return allowActionZPE(action, domainName, resource, roles, matchRoleName);
    }
    
    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     *
     * @param token - either role or access token. For role tokens:
     *        value for the HTTP header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     *        For access tokens: value for HTTP header: Authorization: Bearer access-token
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(String token, String resource, String action) {
        StringBuilder matchRoleName = new StringBuilder(256);
        return allowAccess(token, null, null, resource, action, matchRoleName);
    }
    
    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     * @param token - either role or access token. For role tokens:
     *        value for the HTTP header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     *        For access tokens: value for HTTP header: Authorization: Bearer access-token
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(String token, String resource, String action,
            StringBuilder matchRoleName) {
        return allowAccess(token, null, null, resource, action, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     * @param token either role or access token. For role tokens:
     *        value for the HTTP header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     *        For access tokens: value for HTTP header: Authorization: Bearer access-token
     * @param cert X509 Client Certificate used to establish the mTLS connection
     *        submitting this request
     * @param certHash If the connection is coming through a proxy, this includes
     *        the certificate hash of the client certificate that was calculated
     *        by the proxy and forwarded in a http header
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(String token, X509Certificate cert, String certHash,
            String resource, String action, StringBuilder matchRoleName) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("allowAccess: action={} resource={}", action, resource);
        }

        // check if we're given role or access token

        if (token.startsWith("v=Z1;")) {
            return allowRoleTokenAccess(token, resource, action, matchRoleName);
        } else {
            return allowAccessTokenAccess(token, cert, certHash, resource, action, matchRoleName);
        }
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     * @param token either role or access token. For role tokens:
     *        value for the HTTP header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     *        For access tokens: value for HTTP header: Authorization: Bearer access-token
     * @param cert X509 Client Certificate used to establish the mTLS connection
     *        submitting this request
     * @param certHash If the connection is coming through a proxy, this includes
     *        the certificate hash of the client certificate that was calculated
     *        by the proxy and forwarded in a http header
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(String token, X509Certificate cert, String certHash,
                                                String resource, String action) {
        StringBuilder matchRoleName = new StringBuilder();
        return allowAccess(token, cert, certHash, resource, action, matchRoleName);
    }

    static AccessCheckStatus allowRoleTokenAccess(String roleToken, String resource, String action,
            StringBuilder matchRoleName) {

        Map<String, RoleToken> tokenCache = zpeClt.getRoleTokenCacheMap();
        RoleToken rToken = tokenCache.get(roleToken);

        if (rToken == null) {

            rToken = new RoleToken(roleToken);

            // validate the token. validation also verifies that
            // the token is not expired

            if (!rToken.validate(getZtsPublicKey(rToken.getKeyId()), allowedOffset, false, null)) {

                // check the token expiration and provide a more specific
                // status code to the caller

                if (isTokenExpired(rToken)) {
                    return AccessCheckStatus.DENY_ROLETOKEN_EXPIRED;
                }

                LOG.error("allowAccess: Authorization denied. Authentication failed for token={}",
                        rToken.getUnsignedToken());
                return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
            }

            addTokenToCache(tokenCache, roleToken, rToken);
        }

        return allowAccess(rToken, resource, action, matchRoleName);
    }

    static AccessCheckStatus allowAccessTokenAccess(String accessToken, X509Certificate cert, String certHash,
            String resource, String action, StringBuilder matchRoleName) {

        // if our client sent the full header including Bearer part
        // we're going to strip that out

        if (accessToken.startsWith(BEARER_TOKEN)) {
            accessToken = accessToken.substring(BEARER_TOKEN.length());
        }

        Map<String, AccessToken> tokenCache = zpeClt.getAccessTokenCacheMap();
        AccessToken acsToken = tokenCache.get(accessToken);

        // if we have an x.509 certificate provided then we need to
        // validate our mtls client certificate confirmation value
        // before accepting the token from the cache

        if (acsToken != null && cert != null && !acsToken.confirmMTLSBoundToken(cert, certHash)) {
            LOG.error("allowAccess: mTLS Client certificate confirmation failed");
            return AccessCheckStatus.DENY_CERT_HASH_MISMATCH;
        }

        if (acsToken == null) {

            try {
                if (cert == null && certHash == null) {
                    acsToken = new AccessToken(accessToken, accessSignKeyResolver);
                } else {
                    acsToken = new AccessToken(accessToken, accessSignKeyResolver, cert, certHash);
                }
            } catch (CryptoException ex) {

                LOG.error("allowAccess: Authorization denied. Authentication failed for token={}",
                        ex.getMessage());
                return (ex.getCode() == CryptoException.CERT_HASH_MISMATCH) ?
                        AccessCheckStatus.DENY_CERT_HASH_MISMATCH : AccessCheckStatus.DENY_ROLETOKEN_INVALID;

            } catch (Exception ex) {

                LOG.error("allowAccess: Authorization denied. Authentication failed for token={}",
                        ex.getMessage());
                return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
            }

            addTokenToCache(tokenCache, accessToken, acsToken);
        }

        return allowAccess(acsToken, resource, action, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the RoleToken.
     * @param rToken represents the role token sent by the client that wants access to the resource
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     **/
    public static AccessCheckStatus allowAccess(RoleToken rToken, String resource, String action,
            StringBuilder matchRoleName) {
        
        // check the token expiration

        if (rToken == null) {
            LOG.error("allowAccess: Authorization denied. Token is null");
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (isTokenExpired(rToken)) {
            return AccessCheckStatus.DENY_ROLETOKEN_EXPIRED;
        }

        String tokenDomain = rToken.getDomain(); // ZToken contains the domain
        List<String> roles = rToken.getRoles();  // ZToken contains roles

        return allowActionZPE(action, tokenDomain, resource, roles, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the AccessToken.
     * @param accessToken represents the access token sent by the client that wants access to the resource
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     **/
    public static AccessCheckStatus allowAccess(AccessToken accessToken, String resource, String action,
            StringBuilder matchRoleName) {

        // check the token expiration

        if (accessToken == null) {
            LOG.error("allowAccess: Authorization denied. Token is null");
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (isTokenExpired(accessToken)) {
            return AccessCheckStatus.DENY_ROLETOKEN_EXPIRED;
        }

        String tokenDomain = accessToken.getAudience();
        List<String> roles = accessToken.getScope();

        return allowActionZPE(action, tokenDomain, resource, roles, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the list of role tokens.
     * @param tokenList - list of tokens either role or access. For role tokens
     *        values are from the REST header(s): Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     *        For access tokens values are from the REST header: Authorization
     *        ex: Bearer 123asf341...q234se
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     */
    public static AccessCheckStatus allowAccess(List<String> tokenList,
            String resource, String action, StringBuilder matchRoleName) {

        AccessCheckStatus retStatus = AccessCheckStatus.DENY_NO_MATCH;
        StringBuilder roleName = null;

        for (String roleToken: tokenList) {
            StringBuilder rName = new StringBuilder(256);
            AccessCheckStatus status = allowAccess(roleToken, resource, action, rName);
            if (status == AccessCheckStatus.DENY) {
                matchRoleName.append(rName);
                return status;
            } else if (retStatus != AccessCheckStatus.ALLOW) { // only DENY over-rides ALLOW
                retStatus = status;
                roleName = rName;
            }
        }

        if (roleName != null) {
            matchRoleName.append(roleName);
        }

        return retStatus;
    }

    static boolean isTokenExpired(RoleToken roleToken) {

        long now  = System.currentTimeMillis() / 1000;
        long expiry = roleToken.getExpiryTime();
        if (expiry != 0 && expiry < now) {
            LOG.error("ExpiryCheck: Token expired. now={} expiry={} token={}",
                    now, expiry, roleToken.getUnsignedToken());
            return true;
        }
        return false;
    }

    static boolean isTokenExpired(AccessToken accessToken) {

        long now  = System.currentTimeMillis() / 1000;
        long expiry = accessToken.getExpiryTime();
        if (expiry != 0 && expiry < now) {
            LOG.error("ExpiryCheck: Token expired. now={} expiry={} token={}",
                    now, expiry, accessToken.getClientId());
            return true;
        }
        return false;
    }

    /**
     * Validate the AccessToken and return the parsed token object that
     * could be used to extract all fields from the access token. If the
     * access token is invalid, then null object is returned.
     * @param accessToken - value for the REST header: Authorization
     *        ex: "Bearer authz-token"
     * @param cert X509 Client Certificate used to establish the mTLS connection
     *        submitting this request. can be null if no mtls binding to be verified
     * @param certHash If the connection is coming through a proxy, this includes
     *        the certificate hash of the client certificate that was calculated
     *        by the proxy and forwarded in a http header. can be null if no mtls
     *        mvnbinding to be verified
     * @return AccessToken if the token is validated successfully otherwise null
     */
    public static AccessToken validateAccessToken(String accessToken, X509Certificate cert, String certHash) {

        // if our client sent the full header including Bearer part
        // we're going to strip that out

        if (accessToken.startsWith(BEARER_TOKEN)) {
            accessToken = accessToken.substring(BEARER_TOKEN.length());
        }

        Map<String, AccessToken> tokenCache = zpeClt.getAccessTokenCacheMap();
        AccessToken acsToken = tokenCache.get(accessToken);

        // if we have an x.509 certificate provided then we need to
        // validate our mtls client certificate confirmation value
        // before accepting the token from the cache

        if (acsToken != null && cert != null && !acsToken.confirmMTLSBoundToken(cert, certHash)) {
            return null;
        }

        if (acsToken == null) {

            try {
                if (cert == null && certHash == null) {
                    acsToken = new AccessToken(accessToken, accessSignKeyResolver);
                } else {
                    acsToken = new AccessToken(accessToken, accessSignKeyResolver, cert, certHash);
                }

            } catch (Exception ex) {

                LOG.error("validateAccessToken: Access Token validation failed: {}", ex.getMessage());
                return null;
            }

            addTokenToCache(tokenCache, accessToken, acsToken);
        }

        return acsToken;
    }

    /**
     * Validate the RoleToken and return the parsed token object that
     * could be used to extract all fields from the role token. If the role
     * token is invalid, then null object is returned.
     * @param roleToken - value for the REST header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     * @return RoleToken if the token is validated successfully otherwise null
     */
    public static RoleToken validateRoleToken(String roleToken) {

        // first check in our cache in case we have already seen and successfully
        // validated this role token (signature validation is expensive)
        
        Map<String, RoleToken> tokenCache = zpeClt.getRoleTokenCacheMap();
        RoleToken rToken = tokenCache.get(roleToken);

        if (rToken != null && isTokenExpired(rToken)) {
            tokenCache.remove(roleToken);
            rToken = null;
        }

        // if the token is not in the cache then we need to
        // validate the token now
        
        if (rToken == null) {
            rToken = new RoleToken(roleToken);
            
            // validate the token
            
            if (!rToken.validate(getZtsPublicKey(rToken.getKeyId()), allowedOffset, false, null)) {
                return null;
            }
            addTokenToCache(tokenCache, roleToken, rToken);
        }
        
        return rToken;
    }

    /*
     * Peel off domain name from the assertion string if it matches
     * domain and return the string without the domain prefix.
     * Else, return default value
     */
    static String stripDomainPrefix(String assertString, String domain, String defaultValue) {
        int index = assertString.indexOf(':');
        if (index == -1) {
            return assertString;
        }

        if (!assertString.substring(0, index).equals(domain)) {
            return defaultValue;
        }

        return assertString.substring(index + 1);
    }

    // check action access in the domain to the resource with the given roles

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the given roles. The expected method for authorization
     * check is the allowAccess methods. However, if the client is responsible for
     * validating the role token (including expiration check), it may use this
     * method directly by just specifying the tokenDomain and roles arguments
     * which are directly extracted from the role token.
     * @param action is the type of access attempted by a client
     *        ex: "read"
     *        ex: "scan"
     * @param tokenDomain represents the domain the role token was issued for
     * @param resource is a domain qualified resource the calling service
     *        will check access for.  ex: my_domain:my_resource
     *        ex: "angler:pondsKernCounty"
     *        ex: "sports:service.storage.tenant.Activator.ActionMap"
     * @param roles list of roles extracted from the role token
     * @param matchRoleName - [out] will include the role name that the result was based on
     *        it will be not be set if the failure is due to expired/invalid tokens or
     *        there were no matches thus a default value of DENY_NO_MATCH is returned
     * @return AccessCheckStatus if the user can access the resource via the specified action
     *        the result is ALLOW otherwise one of the DENY_* values specifies the exact
     *        reason why the access was denied
     **/
    public static AccessCheckStatus allowActionZPE(String action, String tokenDomain, String resource,
            List<String> roles, StringBuilder matchRoleName) {

        final String msgPrefix = "allowActionZPE: domain(" + tokenDomain + ") action(" + action +
                ") resource(" + resource + ")";

        if (roles == null || roles.size() == 0) {
            LOG.error("{} ERROR: No roles so access denied", msgPrefix);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("{} roles({}) starting...", msgPrefix, String.join(",", roles));
        }

        if (tokenDomain == null || tokenDomain.isEmpty()) {
            LOG.error("{} ERROR: No domain so access denied", msgPrefix);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (action == null || action.isEmpty()) {
            LOG.error("{} ERROR: No action so access denied", msgPrefix);
            return AccessCheckStatus.DENY_INVALID_PARAMETERS;
        }
        action = action.toLowerCase();

        if (resource == null || resource.isEmpty()) {
            LOG.error("{} ERROR: No resource so access denied", msgPrefix);
            return AccessCheckStatus.DENY_INVALID_PARAMETERS;
        }
        resource = resource.toLowerCase();

        // Note: if domain in token doesn't match domain in resource then there
        // will be no match of any resource in the assertions - so deny immediately
        // special case - when we have a single domain being processed by ZPE
        // the application will never have generated multiple domain values thus
        // if the resource contains : for something else, we'll ignore it and don't
        // assume it's part of the domain separator and thus reject the request.
        // for multiple domains, if the resource might contain :, it's the responsibility
        // of the caller to include the "domain-name:" prefix as part of the resource

        resource = stripDomainPrefix(resource, tokenDomain, zpeClt.getDomainCount() == 1 ? resource : null);
        if (resource == null) {
            LOG.error("{} ERROR: Domain mismatch in token({}) and resource so access denied",
                    msgPrefix, tokenDomain);
            return AccessCheckStatus.DENY_DOMAIN_MISMATCH;
        }

        // first hunt by role for deny assertions since deny takes precedence
        // over allow assertions

        AccessCheckStatus status = AccessCheckStatus.DENY_DOMAIN_NOT_FOUND;
        Map<String, List<Struct>> roleMap = zpeClt.getRoleDenyAssertions(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByRole(action, tokenDomain, resource, roles, roleMap, matchRoleName)) {
                return AccessCheckStatus.DENY;
            } else {
                status = AccessCheckStatus.DENY_NO_MATCH;
            }
        } else if (roleMap != null) {
            status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
        }
        
        // if the check was not explicitly denied by a standard role, then
        // let's process our wildcard roles for deny assertions
        
        roleMap = zpeClt.getWildcardDenyAssertions(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByWildCardRole(action, tokenDomain, resource, roles, roleMap, matchRoleName)) {
                return AccessCheckStatus.DENY;
            } else {
                status = AccessCheckStatus.DENY_NO_MATCH;
            }
        } else if (status != AccessCheckStatus.DENY_NO_MATCH && roleMap != null) {
            status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
        }

        // so far it did not match any deny assertions so now let's
        // process our allow assertions
        
        roleMap = zpeClt.getRoleAllowAssertions(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByRole(action, tokenDomain, resource, roles, roleMap, matchRoleName)) {
                return AccessCheckStatus.ALLOW;
            } else {
                status = AccessCheckStatus.DENY_NO_MATCH;
            }
        } else if (status != AccessCheckStatus.DENY_NO_MATCH && roleMap != null) {
            status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
        }
        
        // at this point we either got an allow or didn't match anything so we're
        // going to try the wildcard roles
        
        roleMap = zpeClt.getWildcardAllowAssertions(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByWildCardRole(action, tokenDomain, resource, roles, roleMap, matchRoleName)) {
                return AccessCheckStatus.ALLOW;
            } else {
                status = AccessCheckStatus.DENY_NO_MATCH;
            }
        } else if (status != AccessCheckStatus.DENY_NO_MATCH && roleMap != null) {
            status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
        }
        
        if (status == AccessCheckStatus.DENY_DOMAIN_NOT_FOUND) {
            LOG.error("{}: No role map found for domain={} so access denied", msgPrefix, tokenDomain);
        } else if (status == AccessCheckStatus.DENY_DOMAIN_EMPTY) {
            LOG.error("{}: No policy assertions for domain={} so access denied", msgPrefix, tokenDomain);
        }
        
        return status;
    }

    static boolean matchAssertions(List<Struct> asserts, String role, String action,
            String resource, StringBuilder matchRoleName, String msgPrefix) {
        
        ZpeMatch matchStruct;
        String passertAction = null;
        String passertResource = null;
        String polName = null;
        
        for (Struct strAssert: asserts) {
            
            if (LOG.isDebugEnabled()) {
                
                // this strings are only used for debug statements so we'll
                // only retrieve them if debug option is enabled
                
                passertAction = strAssert.getString(ZpeConsts.ZPE_FIELD_ACTION);
                passertResource = strAssert.getString(ZpeConsts.ZPE_FIELD_RESOURCE);
                polName = strAssert.getString(ZpeConsts.ZPE_FIELD_POLICY_NAME);

                final String passertRole = strAssert.getString(ZpeConsts.ZPE_FIELD_ROLE);

                LOG.debug("{}: Process Assertion: policy({}) assert-action={} assert-resource={} assert-role={}",
                        msgPrefix, polName, passertAction, passertResource, passertRole);
            }
            
            // ex: "mod*
            
            matchStruct = (ZpeMatch) strAssert.get(ZpeConsts.ZPE_ACTION_MATCH_STRUCT);
            if (!matchStruct.matches(action)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("{}: policy({}) regexpr-match: FAILed: assert-action({}) doesn't match action({})",
                            msgPrefix, polName, passertAction, action);
                }
                continue;
            }
            
            // ex: "weather:service.storage.tenant.sports.*"
            matchStruct = (ZpeMatch) strAssert.get(ZpeConsts.ZPE_RESOURCE_MATCH_STRUCT);
            if (!matchStruct.matches(resource)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("{}: policy({}) regexpr-match: FAILed: assert-resource({}) doesn't match resource({})",
                            msgPrefix, polName, passertResource, resource);
                }
                continue;
            }
            
            // update the match role name
            
            matchRoleName.setLength(0);
            matchRoleName.append(role);
            
            return true;
        }
        
        return false;
    }
    
    static boolean actionByRole(String action, String domain, String resource,
            List<String> roles, Map<String, List<Struct>> roleMap, StringBuilder matchRoleName) {

        // msgPrefix is only used in our debug statements so we're only
        // going to generate the value if debug is enabled
        
        String msgPrefix = null;
        if (LOG.isDebugEnabled()) {
            msgPrefix = "allowActionByRole: domain(" + domain + ") action(" + action +
                    ") resource(" + resource + ")";
        }
        
        for (String role : roles) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("{}: Process role ({})", msgPrefix, role);
            }

            List<Struct> asserts = roleMap.get(role);
            if (asserts == null || asserts.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("{}: No policy assertions in domain={} for role={} so access denied",
                            msgPrefix, domain, role);
                }
                continue;
            }

            // see if any of its assertions match the action and resource
            // the assert action value does not have the domain prefix
            // ex: "Modify"
            // the assert resource value has the domain prefix
            // ex: "angler:angler.stuff"
            
            if (matchAssertions(asserts, role, action, resource, matchRoleName, msgPrefix)) {
                return true;
            }
        }
        
        return false;
    }

    static boolean actionByWildCardRole(String action, String domain, String resource,
            List<String> roles, Map<String, List<Struct>> roleMap, StringBuilder matchRoleName) {

        String msgPrefix = null;
        if (LOG.isDebugEnabled()) {
            msgPrefix = "allowActionByWildCardRole: domain(" + domain + ") action(" + action +
                    ") resource(" + resource + ")";
        }

        // find policy matching resource and action
        // get assertions for given domain+role
        // then cycle thru those assertions looking for matching action and resource

        // we will visit each of the wildcard roles
        //
        Set<String> keys = roleMap.keySet();

        for (String role: roles) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("{}: Process role ({})", msgPrefix, role);
            }

            for (String roleName : keys) {
                List<Struct> asserts = roleMap.get(roleName);
                if (asserts == null || asserts.isEmpty()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{}: No policy assertions in domain={} for role={} so access denied",
                                msgPrefix, domain, role);
                    }
                    continue;
                }

                Struct structAssert = asserts.get(0);
                ZpeMatch matchStruct = (ZpeMatch) structAssert.get(ZpeConsts.ZPE_ROLE_MATCH_STRUCT);
                if (!matchStruct.matches(role)) {
                    if (LOG.isDebugEnabled()) {
                        final String polName = structAssert.getString(ZpeConsts.ZPE_FIELD_POLICY_NAME);
                        LOG.debug("{}: policy({}) regexpr-match: FAILed: assert-role({}) doesnt match role({})",
                                msgPrefix, polName, roleName, role);
                    }
                    continue;
                }
                
                // HAVE: matched the role with the wildcard

                // see if any of its assertions match the action and resource
                // the assert action value does not have the domain prefix
                // ex: "Modify"
                // the assert resource value has the domain prefix
                // ex: "angler:angler.stuff"
                
                if (matchAssertions(asserts, roleName, action, resource, matchRoleName, msgPrefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    static boolean certIssuerMatch(X509Certificate cert) {

        // first check if we have any issuers configured

        if (X509_ISSUERS_NAMES.isEmpty()) {
            return true;
        }

        X500Principal issuerX500Principal = cert.getIssuerX500Principal();
        final String issuer = issuerX500Principal.getName();

        if (!issuerMatch(issuer)) {
            LOG.error("certIssuerMatch: missing or mismatch issuer {}", issuer);
            return false;
        }

        return true;
    }

    static boolean issuerMatch(final String issuer) {

        // verify we have a valid issuer before any checks

        if (issuer == null || issuer.isEmpty()) {
            return false;
        }

        // first we're going to check our quick check
        // using the issuer as is without any rdn compare

        if (X509_ISSUERS_NAMES.contains(issuer.replaceAll("\\s+" , ""))) {
            return true;
        }

        // we're going to do more expensive rdn match

        try {
            X500Principal issuerCheck = new X500Principal(issuer);
            List<Rdn> issuerRdns = new LdapName(issuerCheck.getName()).getRdns();

            for (List<Rdn> rdns : X509_ISSUERS_RDNS) {
                if (rdns.size() != issuerRdns.size()) {
                    continue;
                }
                if (rdns.containsAll(issuerRdns)) {
                    return true;
                }
            }
        } catch (InvalidNameException ignored) {
            // the caller will log the failure
        }

        return false;
    }

    static <T> void addTokenToCache(Map<String, T> tokenCache, final String tokenKey, T tokenValue) {
        if (maxTokenCacheSize == 0 || tokenCache.size() < maxTokenCacheSize) {
            tokenCache.put(tokenKey, tokenValue);
        }
    }

    public static void main(String[] args) {

        if (args.length != 3) {
            System.out.println("usage: AuthZpeClient <authz-token> <action> <resource>");
            System.exit(1);
        }

        final String authzToken = args[0];
        final String action = args[1];
        final String resource = args[2];

        StringBuilder matchRoleName = new StringBuilder();
        AuthZpeClient.init();
        AccessCheckStatus status = AuthZpeClient.allowAccess(authzToken, resource, action, matchRoleName);
        System.out.println(status.toString() + ":" + matchRoleName);
        System.exit(0);
    }
}

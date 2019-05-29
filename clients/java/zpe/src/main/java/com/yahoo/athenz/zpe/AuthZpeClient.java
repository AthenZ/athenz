/*
 * Copyright 2016 Yahoo Inc.
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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.athenz.zpe.pkey.PublicKeyStoreFactory;
import com.yahoo.rdl.Struct;

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
    
    public static ZpeMetric zpeMetric = new ZpeMetric();

    private static String zpeClientImplName;
    private static int allowedOffset = 300;
    private static JwtsSigningKeyResolver accessSignKeyResolver = null;

    private static ZpeClient zpeClt = null;
    private static PublicKeyStore publicKeyStore = null;

    private static final Set<String> X509_ISSUERS_NAMES = new HashSet<>();
    private static final List<List<Rdn>> X509_ISSUERS_RDNS = new ArrayList<>();

    private static final String ROLE_SEARCH = ":role.";
    
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
                return "Access denied due to expired RoleToken";
            }
        },
        DENY_ROLETOKEN_INVALID {
            public String toString() {
                return "Access denied due to invalid RoleToken";
            }
        },
        DENY_DOMAIN_MISMATCH {
            public String toString() {
                return "Access denied due to domain mismatch between Resource and RoleToken";
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
        }
    }
    
    static {

        // load public keys

        setPublicKeyStoreFactoryClass(System.getProperty(ZpeConsts.ZPE_PROP_PUBLIC_KEY_CLASS, ZPE_PKEY_CLASS));

        // instantiate implementation classes
        
        setZPEClientClass(System.getProperty(ZpeConsts.ZPE_PROP_CLIENT_IMPL, ZPE_UPDATER_CLASS));

        // set the allowed offset
        
        setTokenAllowedOffset(Integer.parseInt(System.getProperty(ZpeConsts.ZPE_PROP_TOKEN_OFFSET, "300")));

        // load the x509 issuers
        
        setX509CAIssuers(System.getProperty(ZpeConsts.ZPE_PROP_X509_CA_ISSUERS));

        // initialize the access token signing key resolver

        setAccessTokenSingKeyResolver(null, null);
    }
    
    public static void init() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Init: load the ZPE");
        }
    }

    /**
     * Set the role token allowed offset. this might be necessary
     * if the client and server are not ntp synchronized and we
     * don't want the server to reject valid role tokens
     * @param offset value in seconds
     */
    public static void setTokenAllowedOffset(int offset) {
        
        allowedOffset = offset;
        
        // case of invalid value, we'll default back to 5 minutes

        if (allowedOffset < 0) {
            allowedOffset = 300;
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
            LOG.error("Invalid PublicKeyStore class: " + className
                    + ", error: " + ex.getMessage());
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
    public static void setAccessTokenSingKeyResolver(final String serverUrl, SSLContext sslContext) {
        accessSignKeyResolver = new JwtsSigningKeyResolver(serverUrl, sslContext);
    }

    /**
     * Include the specified public key and id in the access token
     * signing resolver
     * @param keyId public key id
     * @param key public key for the given id
     */
    public static void addAccessTokenSingKeyResolverKey(final String keyId, PublicKey key) {
        accessSignKeyResolver.addPublicKey(keyId, key);
    }

    /**
     * Set the ZPE Client implementation class name in case the default
     * ZPE client is not sufficient for some reason.
     * @param className ZPE Client implementation class name
     */
    public static void setZPEClientClass(final String className) {
        
        zpeClientImplName = className;
        try {
            zpeClt = (ZpeClient) Class.forName(zpeClientImplName).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
            LOG.error("Unable to instantiate zpe class: " + zpeClientImplName
                    + ", error: " + ex.getMessage());
            throw new RuntimeException(ex);
        }
        zpeClt.init(null);
    }
    
    public static PublicKey getZtsPublicKey(String keyId) {
        return publicKeyStore.getZtsKey(keyId);
    }
    
    public static PublicKey getZmsPublicKey(String keyId) {
        return publicKeyStore.getZmsKey(keyId);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the X509Certificate
     * @param cert - X509Certificate
     *
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
     * @param cert - X509Certificate
     *
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
        zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME, DEFAULT_DOMAIN);

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

        int idx = subject.indexOf(ROLE_SEARCH);
        if (idx == -1) {
            LOG.error("allowAccess: invalid role format in x.509 subject: {}", subject);
            return AccessCheckStatus.DENY_CERT_MISSING_ROLE_NAME;
        }

        String domainName = subject.substring(0, idx);
        if (domainName.isEmpty()) {
            LOG.error("allowAccess: missing domain in x.509 subject: {}", subject);
            return AccessCheckStatus.DENY_CERT_MISSING_DOMAIN;
        }

        String roleName = subject.substring(idx + ROLE_SEARCH.length());
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
     * @param roleToken - value for the REST header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
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
    public static AccessCheckStatus allowAccess(String roleToken, String resource, String action) {
        StringBuilder matchRoleName = new StringBuilder(256);
        return allowAccess(roleToken, resource, action, matchRoleName);
    }
    
    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     * @param token - either role of access token. For role tokens:
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

        if (LOG.isDebugEnabled()) {
            LOG.debug("allowAccess: action={} resource={}", action, resource);
        }
        zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME, DEFAULT_DOMAIN);

        // check if we're given role or access token

        if (token.startsWith("v=Z1;")) {
            return allowRoleTokenAccess(token, resource, action, matchRoleName);
        } else {
            return allowAccessTokenAccess(token, resource, action, matchRoleName);
        }
    }

    static AccessCheckStatus allowRoleTokenAccess(String roleToken, String resource, String action,
            StringBuilder matchRoleName) {

        Map<String, RoleToken> tokenCache = zpeClt.getRoleTokenCacheMap();
        RoleToken rToken = tokenCache.get(roleToken);

        if (rToken == null) {

            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_NOT_FOUND, DEFAULT_DOMAIN);
            rToken = new RoleToken(roleToken);

            // validate the token. validation also verifies that
            // the token is not expired

            if (!rToken.validate(getZtsPublicKey(rToken.getKeyId()), allowedOffset, false, null)) {

                // check the token expiration and provide a more specific
                // status code to the caller

                if (isTokenExpired(rToken)) {
                    zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_EXPIRED_TOKEN, rToken.getDomain());
                    return AccessCheckStatus.DENY_ROLETOKEN_EXPIRED;
                }

                LOG.error("allowAccess: Authorization denied. Authentication failed for token={}",
                        rToken.getUnsignedToken());
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, rToken.getDomain());
                return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
            }
            tokenCache.put(roleToken, rToken);
        } else {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_SUCCESS, rToken.getDomain());
        }

        return allowAccess(rToken, resource, action, matchRoleName);
    }

    static AccessCheckStatus allowAccessTokenAccess(String accessToken, String resource,
            String action, StringBuilder matchRoleName) {

        Map<String, AccessToken> tokenCache = zpeClt.getAccessTokenCacheMap();;
        AccessToken acsToken = tokenCache.get(accessToken);

        if (acsToken == null) {

            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_NOT_FOUND, DEFAULT_DOMAIN);

            try {
                acsToken = new AccessToken(accessToken, accessSignKeyResolver);
            } catch (Exception ex) {

                LOG.error("allowAccess: Authorization denied. Authentication failed for token={}",
                        ex.getMessage());
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, DEFAULT_DOMAIN);
                return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
            }

            tokenCache.put(accessToken, acsToken);

        } else {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_SUCCESS, acsToken.getAudience());
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
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, UNKNOWN_DOMAIN);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (isTokenExpired(rToken)) {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_EXPIRED_TOKEN, rToken.getDomain());
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
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, UNKNOWN_DOMAIN);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (isTokenExpired(accessToken)) {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_EXPIRED_TOKEN, accessToken.getAudience());
            return AccessCheckStatus.DENY_ROLETOKEN_EXPIRED;
        }

        String tokenDomain = accessToken.getAudience();
        List<String> roles = accessToken.getScope();

        return allowActionZPE(action, tokenDomain, resource, roles, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the list of role tokens.
     * @param roleTokenList - values from the REST header(s): Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
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
    public static AccessCheckStatus allowAccess(List<String> roleTokenList,
            String resource, String action, StringBuilder matchRoleName) {

        AccessCheckStatus retStatus = AccessCheckStatus.DENY_NO_MATCH;
        StringBuilder roleName = null;

        for (String roleToken: roleTokenList) {
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
            matchRoleName.append(roleName.toString());
        }

        return retStatus;
    }

    static boolean isTokenExpired(RoleToken roleToken) {

        long now  = System.currentTimeMillis() / 1000;
        long expiry = roleToken.getExpiryTime();
        if (expiry != 0 && expiry < now) {
            LOG.error("ExpiryCheck: Token expired. now={} expiry={} token={}" +
                    now, expiry, roleToken.getUnsignedToken());
            return true;
        }
        return false;
    }

    static boolean isTokenExpired(AccessToken accessToken) {

        long now  = System.currentTimeMillis() / 1000;
        long expiry = accessToken.getExpiryTime();
        if (expiry != 0 && expiry < now) {
            LOG.error("ExpiryCheck: Token expired. now={} expiry={} token={}" +
                    now, expiry, accessToken.getClientId());
            return true;
        }
        return false;
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
            tokenCache.put(roleToken, rToken);
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
    
    static boolean isRegexMetaCharacter(char regexChar) {
        switch (regexChar) {
            case '^':
            case '$':
            case '.':
            case '|':
            case '[':
            case '+':
            case '\\':
            case '(':
            case ')':
            case '{':
                return true;
            default:
                return false;
        }
    }
    
    public static String patternFromGlob(String glob) {
        StringBuilder sb = new StringBuilder("^");
        int len = glob.length();
        for (int i = 0; i < len; i++) {
            char c = glob.charAt(i);
            if (c == '*') {
                sb.append(".*");
            } else if (c == '?') {
                sb.append('.');
            } else {
                if (isRegexMetaCharacter(c)) {
                    sb.append('\\');
                }
                sb.append(c);
            }
        }
        sb.append("$");
        return sb.toString();
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
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, tokenDomain);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("{} roles({}) starting...", msgPrefix, String.join(",", roles));
        }

        if (tokenDomain == null || tokenDomain.isEmpty()) {
            LOG.error("{} ERROR: No domain so access denied", msgPrefix);
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, DEFAULT_DOMAIN);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (action == null || action.isEmpty()) {
            LOG.error("{} ERROR: No action so access denied", msgPrefix);
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ERROR, tokenDomain);
            return AccessCheckStatus.DENY_INVALID_PARAMETERS;
        }
        action = action.toLowerCase();

        if (resource == null || resource.isEmpty()) {
            LOG.error("{} ERROR: No resource so access denied", msgPrefix);
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ERROR, tokenDomain);
            return AccessCheckStatus.DENY_INVALID_PARAMETERS;
        }
        resource = resource.toLowerCase();
        resource = stripDomainPrefix(resource, tokenDomain, null);

        // Note: if domain in token doesn't match domain in resource then there
        // will be no match of any resource in the assertions - so deny immediately

        if (resource == null) {
            LOG.error("{} ERROR: Domain mismatch in token({}) and resource so access denied",
                    msgPrefix, tokenDomain);
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DOMAIN_MISMATCH, tokenDomain);
            return AccessCheckStatus.DENY_DOMAIN_MISMATCH;
        }

        // first hunt by role for deny assertions since deny takes precedence
        // over allow assertions

        AccessCheckStatus status = AccessCheckStatus.DENY_DOMAIN_NOT_FOUND;
        Map<String, List<Struct>> roleMap = zpeClt.getRoleDenyAssertions(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByRole(action, tokenDomain, resource, roles, roleMap, matchRoleName)) {
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DENY, tokenDomain);
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
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DENY, tokenDomain);
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
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ALLOW, tokenDomain);
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
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ALLOW, tokenDomain);
                return AccessCheckStatus.ALLOW;
            } else {
                status = AccessCheckStatus.DENY_NO_MATCH;
            }
        } else if (status != AccessCheckStatus.DENY_NO_MATCH && roleMap != null) {
            status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
        }
        
        if (status == AccessCheckStatus.DENY_DOMAIN_NOT_FOUND) {
            LOG.error("{}: No role map found for domain={} so access denied", msgPrefix, tokenDomain);
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DOMAIN_NOT_FOUND, tokenDomain);
        } else if (status == AccessCheckStatus.DENY_DOMAIN_EMPTY) {
            LOG.error("{}: No policy assertions for domain={} so access denied", msgPrefix, tokenDomain);
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DOMAIN_EMPTY, tokenDomain);
        } else {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DENY_NO_MATCH, tokenDomain);
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

    public static void main(String[] args) {

        if (args.length != 3) {
            System.out.println("usage: AuthZpeClient <role-token> <action> <resource>");
            System.exit(1);
        }

        final String roleToken = args[0];
        final String action = args[1];
        final String resource = args[2];

        AuthZpeClient.init();
        System.out.println("Authorization Response: "
                + AuthZpeClient.allowAccess(roleToken, action, resource).toString());
    }
}

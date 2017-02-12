/**
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

import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.athenz.zpe.pkey.PublicKeyStoreFactory;
import com.yahoo.rdl.Struct;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthZpeClient {

    private static final Logger LOG = LoggerFactory.getLogger(AuthZpeClient.class);
    
    public static final String ZPE_UPDATER_CLASS = "com.yahoo.athenz.zpe.ZpeUpdater";
    public static final String ZPE_PKEY_CLASS = "com.yahoo.athenz.zpe.pkey.file.FilePublicKeyStoreFactory";

    public static final String ZPE_TOKEN_HDR  = System.getProperty(RoleAuthority.ATHENZ_PROP_ROLE_HEADER, RoleAuthority.HTTP_HEADER);;

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

    private static ZpeClient zpeClt = null;
    private static PublicKeyStore publicKeyStore = null;

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
            };
        }
    }
    
    static {

        // instantiate implementation classes
        
        zpeClientImplName = System.getProperty(ZpeConsts.ZPE_PROP_CLIENT_IMPL, ZPE_UPDATER_CLASS);
        try {
            zpeClt = getZpeClient();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
            LOG.error("Unable to instantiate zpe class: " + zpeClientImplName
                    + ", error: " + ex.getMessage());
            throw new RuntimeException(ex);
        }
        zpeClt.init(null);

        allowedOffset = Integer.parseInt(System.getProperty(ZpeConsts.ZPE_PROP_TOKEN_OFFSET, "300"));

        // case of invalid value, we'll default back to 5 minutes

        if (allowedOffset < 0) {
            allowedOffset = 300;
        }
        
        String pkeyFactoryClass = System.getProperty(ZpeConsts.ZPE_PROP_PUBLIC_KEY_CLASS, ZPE_PKEY_CLASS);

        PublicKeyStoreFactory publicKeyStoreFactory = null;
        try {
            publicKeyStoreFactory = (PublicKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
            LOG.error("Invalid PublicKeyStore class: " + pkeyFactoryClass
                    + ", error: " + ex.getMessage());
            throw new RuntimeException(ex);
        }
        publicKeyStore = publicKeyStoreFactory.create();
    }
    
    public static void init() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Init: load the ZPE");
        }
    }

    public static PublicKey getZtsPublicKey(String keyId) {
        return publicKeyStore.getZtsKey(keyId);
    }
    
    public static PublicKey getZmsPublicKey(String keyId) {
        return publicKeyStore.getZmsKey(keyId);
    }
    
    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     * @param roleToken - value for the REST header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     * @param angResource is a domain qualified resource the calling service
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
    public static AccessCheckStatus allowAccess(String roleToken, String angResource, String action) {
        StringBuilder matchRoleName = new StringBuilder(256);
        return allowAccess(roleToken, angResource, action, matchRoleName);
    }
    
    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the user (cltToken, cltTokenName).
     * @param roleToken - value for the REST header: Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     * @param angResource is a domain qualified resource the calling service
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
    public static AccessCheckStatus allowAccess(String roleToken, String angResource, String action,
            StringBuilder matchRoleName) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("allowAccess: action=" + action + " resource=" + angResource);
        }
        zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME, DEFAULT_DOMAIN);

        RoleToken rToken = null;
        Map<String, RoleToken> tokenCache = null;
        try {
            ZpeClient zpeclt = getZpeClient();
            tokenCache = zpeclt.getRoleTokenCacheMap();
            rToken = tokenCache.get(roleToken);
        } catch (Exception exc) {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_FAILURE, DEFAULT_DOMAIN);
            LOG.error("allowAccess: token cache failure, exc: " + exc.getMessage());
        }

        if (rToken == null) {

            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_NOT_FOUND, DEFAULT_DOMAIN);
            rToken = new RoleToken(roleToken);

            // validate the token
            if (rToken.validate(getZtsPublicKey(rToken.getKeyId()), allowedOffset, null) == false) {
                LOG.error("allowAccess: Authorization denied. Authentication of token failed for token="
                        + rToken.getSignedToken());
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, rToken.getDomain());
                return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
            }

            if (tokenCache != null) {
                tokenCache.put(roleToken, rToken);
            }
        } else {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_CACHE_SUCCESS, rToken.getDomain());
        }
        
        AccessCheckStatus status = allowAccess(rToken, angResource, action, matchRoleName);
        return status;
    }
 
    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the RoleToken.
     * @param rToken represents the role token sent by the client that wants access to the resource
     * @param angResource is a domain qualified resource the calling service
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
    public static AccessCheckStatus allowAccess(RoleToken rToken, String angResource, String action,
            StringBuilder matchRoleName) {
        
        // check the token expiration
        if (rToken == null) {
            LOG.error("allowAccess: Authorization denied. Token is null");
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, UNKNOWN_DOMAIN);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }
        long now    = System.currentTimeMillis() / 1000;
        long expiry = rToken.getExpiryTime();
        if (expiry != 0 && expiry < now) {
            String signedToken = rToken.getSignedToken();
            LOG.error("allowAccess: Authorization denied. Token expired. now=" +
                    now + " expiry=" + expiry + " token=" + signedToken);
            Map<String, RoleToken> tokenCache = null;
            try {
                ZpeClient zpeclt = getZpeClient();
                tokenCache = zpeclt.getRoleTokenCacheMap();
                tokenCache.remove(signedToken);
            } catch (Exception exc) {
                LOG.error("allowAccess: token cache failure, exc: " + exc.getMessage());
            }

            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_EXPIRED_TOKEN, rToken.getDomain());
            return AccessCheckStatus.DENY_ROLETOKEN_EXPIRED;
        }

        String tokenDomain = rToken.getDomain(); // ZToken contains the domain
        List<String> roles = rToken.getRoles();  // ZToken contains roles

        if (LOG.isDebugEnabled()) {
            if (roles != null) {
                for (String role: roles) { 
                    LOG.debug("allowAccess: token role=" + role);
                }
            }
        }

        return allowActionZPE(action, tokenDomain, angResource, roles, matchRoleName);
    }

    /**
     * Determine if access(action) is allowed against the specified resource by
     * a user represented by the list of role tokens.
     * @param roleTokenList - values from the REST header(s): Athenz-Role-Auth
     *        ex: "v=Z1;d=angler;r=admin;a=aAkjbbDMhnLX;t=1431974053;e=1431974153;k=0"
     * @param angResource is a domain qualified resource the calling service
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
            String angResource, String action, StringBuilder matchRoleName) {

        AccessCheckStatus retStatus = AccessCheckStatus.DENY_NO_MATCH;
        StringBuilder     roleName  = null;
        for (String roleToken: roleTokenList) {
            StringBuilder rName = new StringBuilder(64);
            AccessCheckStatus status = allowAccess(roleToken, angResource, action, rName);
            if (status == AccessCheckStatus.DENY) {
                matchRoleName.append(rName);
                return status;
            } else if (retStatus != AccessCheckStatus.ALLOW) { // only DENY over-rides ALLOW
                retStatus = status;
                roleName  = rName;
            }
        }

        if (roleName != null) {
            matchRoleName.append(roleName.toString());
        }

        return retStatus;
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

        RoleToken rToken = null;
        
        // first check in our cache in case we have already seen and successfully
        // validated this role token (signature validation is expensive)
        
        Map<String, RoleToken> tokenCache = null;
        try {
            ZpeClient zpeclt = getZpeClient();
            tokenCache = zpeclt.getRoleTokenCacheMap();
            rToken = tokenCache.get(roleToken);
        } catch (Exception exc) {
        }

        // if the token is not in the cache then we need to
        // validate the token now
        
        if (rToken == null) {
            rToken = new RoleToken(roleToken);
            
            // validate the token
            
            if (rToken.validate(getZtsPublicKey(rToken.getKeyId()), allowedOffset, null) == false) {
                return null;
            }

            if (tokenCache != null) {
                tokenCache.put(roleToken, rToken);
            }
        }
        
        return rToken;
    }
    
    static ZpeClient getZpeClient() throws InstantiationException, IllegalAccessException, ClassNotFoundException {

        if (zpeClt != null) {
            return zpeClt;
        }
        
        return (ZpeClient) Class.forName(zpeClientImplName).newInstance();
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

        if (assertString.substring(0, index).equals(domain) == false) {
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
    //
    static AccessCheckStatus allowActionZPE(String action, String tokenDomain, String angResource,
            List<String> roles, StringBuilder matchRoleName) {

        StringBuilder sb = new StringBuilder("allowActionZPE: domain(");
        sb.append(tokenDomain).append(") action(").append(action).
           append(") resource(").append(angResource).append(")");
        String msgPrefix = sb.toString();

        if (LOG.isDebugEnabled()) {
            LOG.debug(msgPrefix + " STARTING");
        }

        if (roles == null || roles.size() == 0) {
            LOG.error(msgPrefix + " ERROR: No roles so access denied");
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, tokenDomain);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (tokenDomain == null || tokenDomain.isEmpty() == true) {
            LOG.error(msgPrefix + " ERROR: No domain so access denied");
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_INVALID_TOKEN, DEFAULT_DOMAIN);
            return AccessCheckStatus.DENY_ROLETOKEN_INVALID;
        }

        if (action == null || action.isEmpty() == true) {
            LOG.error(msgPrefix + " ERROR: No action so access denied");
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ERROR, tokenDomain);
            return AccessCheckStatus.DENY_INVALID_PARAMETERS;
        }
        action = action.toLowerCase();

        if (angResource == null || angResource.isEmpty() == true) {
            LOG.error(msgPrefix + " ERROR: No resource so access denied");
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ERROR, tokenDomain);
            return AccessCheckStatus.DENY_INVALID_PARAMETERS;
        }
        angResource = angResource.toLowerCase();
        angResource = stripDomainPrefix(angResource, tokenDomain, null);

        // Note: if domain in token doesn't match domain in resource then there
        // will be no match of any resource in the assertions - so deny immediately

        if (angResource == null) {
            StringBuilder sbErr = new StringBuilder(512);
            sbErr.append(msgPrefix).append(" ERROR: Domain mismatch in token(").
                append(tokenDomain).append(") and resource so access denied");
            LOG.error(sbErr.toString());
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DOMAIN_MISMATCH, tokenDomain);
            return AccessCheckStatus.DENY_DOMAIN_MISMATCH;
        }

        // first hunt by role for deny assertions since deny takes precedence
        // over allow assertions

        AccessCheckStatus status = AccessCheckStatus.DENY_DOMAIN_NOT_FOUND;
        Map<String, List<Struct>> roleMap = getRoleSpecificDenyPolicies(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByRole(action, tokenDomain, angResource, roles, roleMap, matchRoleName)) {
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
        
        roleMap = getWildCardDenyPolicies(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByWildCardRole(action, tokenDomain, angResource, roles, roleMap, matchRoleName)) {
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
        
        roleMap = getRoleSpecificAllowPolicies(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByRole(action, tokenDomain, angResource, roles, roleMap, matchRoleName)) {
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
        
        roleMap = getWildCardAllowPolicies(tokenDomain);
        if (roleMap != null && !roleMap.isEmpty()) {
            if (actionByWildCardRole(action, tokenDomain, angResource, roles, roleMap, matchRoleName)) {
                zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_ALLOW, tokenDomain);
                return AccessCheckStatus.ALLOW;
            } else {
                status = AccessCheckStatus.DENY_NO_MATCH;
            }
        } else if (status != AccessCheckStatus.DENY_NO_MATCH && roleMap != null) {
            status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
        }
        
        if (status == AccessCheckStatus.DENY_DOMAIN_NOT_FOUND) {
            if (LOG.isDebugEnabled()) {
                    LOG.debug(msgPrefix + ": No role map found for domain=" + tokenDomain
                        + " so access denied");
            }
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DOMAIN_NOT_FOUND, tokenDomain);
        } else if (status == AccessCheckStatus.DENY_DOMAIN_EMPTY) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(msgPrefix + ": No policy assertions for domain=" + tokenDomain
                        + " so access denied");
            }
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DOMAIN_EMPTY, tokenDomain);
        } else {
            zpeMetric.increment(ZpeConsts.ZPE_METRIC_NAME_DENY_NO_MATCH, tokenDomain);
        }
        
        return status;
    }

    static boolean matchAssertions(List<Struct> asserts, String role, String action,
            String resource, StringBuilder matchRoleName, String msgPrefix) {
        
        ZpeMatch matchStruct = null;
        String passertAction = null;
        String passertResource = null;
        String passertRole  = null;
        String polName = null;
        
        for (Struct strAssert: asserts) {
            
            if (LOG.isDebugEnabled()) {
                
                // this strings are only used for debug statements so we'll
                // only retrieve them if debug option is enabled
                
                passertAction   = strAssert.getString(ZpeConsts.ZPE_FIELD_ACTION);
                passertResource = strAssert.getString(ZpeConsts.ZPE_FIELD_RESOURCE);
                passertRole     = strAssert.getString(ZpeConsts.ZPE_FIELD_ROLE);
                polName         = strAssert.getString(ZpeConsts.ZPE_FIELD_POLICY_NAME);
                
                LOG.debug(msgPrefix + ": Process Assertion: policy(" + polName +
                    ") assert-action=" + passertAction +
                    " assert-resource=" + passertResource + " assert-role=" + passertRole);
            }
            
            // ex: "mod*
            
            matchStruct = (ZpeMatch) strAssert.get(ZpeConsts.ZPE_ACTION_MATCH_STRUCT);
            if (!matchStruct.matches(action)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msgPrefix + ": policy(" + polName + ") regexpr-match: FAILed: assert-action("
                            + passertAction + ") doesn't match action(" + action + ")");
                }
                continue;
            }
            
            // ex: "weather:service.storage.tenant.sports.*"
            matchStruct = (ZpeMatch) strAssert.get(ZpeConsts.ZPE_RESOURCE_MATCH_STRUCT);
            if (!matchStruct.matches(resource)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msgPrefix + ": policy(" + polName + ") regexpr-match: FAILed: assert-resource("
                            + passertResource + ") doesn't match resource(" + resource + ")");
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
    
    static boolean actionByRole(String action, String domain, String angResource,
            List<String> roles, Map<String, List<Struct>> roleMap, StringBuilder matchRoleName) {

        // msgPrefix is only used in our debug statements so we're only
        // going to generate the value if debug is enabled
        
        String msgPrefix = null;
        if (LOG.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder("allowActionByRole: domain(");
            sb.append(domain).append(") action(").append(action).
                append(") resource(").append(angResource).append(")");
            msgPrefix = sb.toString();
        }
        
        for (String role : roles) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(msgPrefix + ": Process role (" + role + ")");
            }

            List<Struct> asserts = roleMap.get(role);
            if (asserts == null || asserts.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msgPrefix + ": No policy assertions in domain=" + domain
                        + " for role=" + role + " so access denied");
                }
                continue;
            }

            // see if any of its assertions match the action and resource
            // the assert action value does not have the domain prefix
            // ex: "Modify"
            // the assert resource value has the domain prefix
            // ex: "angler:angler.stuff"
            
            if (matchAssertions(asserts, role, action, angResource, matchRoleName, msgPrefix)) {
                return true;
            }
        }
        
        return false;
    }

    static boolean actionByWildCardRole(String action, String domain, String angResource,
            List<String> roles, Map<String, List<Struct>> roleMap, StringBuilder matchRoleName) {

        String msgPrefix = null;
        if (LOG.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder("allowActionByWildCardRole: domain(");
            sb.append(domain).append(") action(").append(action).
                append(") resource(").append(angResource).append(")");
            msgPrefix = sb.toString();
        }

        // find policy matching resource and action
        // get assertions for given domain+role
        // then cycle thru those assertions looking for matching action and resource

        // we will visit each of the wildcard roles
        //
        Set<String> keys = roleMap.keySet();

        for (String role: roles) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(msgPrefix + ": Process role (" + role + ")");
            }

            for (String roleName : keys) {
                List<Struct> asserts = roleMap.get(roleName);
                if (asserts == null || asserts.isEmpty()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(msgPrefix + ": No policy assertions in domain=" + domain
                            + " for role=" + role + " so access denied");
                    }
                    continue;
                }

                Struct structAssert = asserts.get(0);
                ZpeMatch matchStruct = (ZpeMatch) structAssert.get(ZpeConsts.ZPE_ROLE_MATCH_STRUCT);
                if (!matchStruct.matches(role)) {
                    if (LOG.isDebugEnabled()) {
                        String polName = structAssert.getString(ZpeConsts.ZPE_FIELD_POLICY_NAME);
                        LOG.debug(msgPrefix + ": policy(" + polName +
                            ") regexpr-match: FAILed: assert-role(" + roleName +
                            ") doesnt match role(" + role + ")");
                    }
                    continue;
                }
                
                // HAVE: matched the role with the wildcard

                // see if any of its assertions match the action and resource
                // the assert action value does not have the domain prefix
                // ex: "Modify"
                // the assert resource value has the domain prefix
                // ex: "angler:angler.stuff"
                
                if (matchAssertions(asserts, roleName, action, angResource, matchRoleName, msgPrefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    static Map<String, List<Struct>> getWildCardAllowPolicies(String domain) {
        try {
            ZpeClient zpeclt = getZpeClient();
            Map<String, List<Struct>> roleAsserts = zpeclt.getWildcardAllowAssertions(domain);
            return roleAsserts;
        } catch (Exception exc) {
            LOG.error("getWildCardAllowPolicies: exc: " + exc.getMessage());
        }
        return null;
    }

    static Map<String, List<Struct>> getRoleSpecificAllowPolicies(String domain) {
        try {
            ZpeClient zpeclt = getZpeClient();
            Map<String, List<Struct>> roleAsserts = zpeclt.getRoleAllowAssertions(domain);
            return roleAsserts;
        } catch (Exception exc) {
            LOG.error("getRoleSpecificAllowPolicies: exc: " + exc.getMessage());
        }
        return null;
    }
    
    static Map<String, List<Struct>> getWildCardDenyPolicies(String domain) {
        try {
            ZpeClient zpeclt = getZpeClient();
            Map<String, List<Struct>> roleAsserts = zpeclt.getWildcardDenyAssertions(domain);
            return roleAsserts;
        } catch (Exception exc) {
            LOG.error("getWildCardDenyPolicies: exc: " + exc.getMessage());
        }
        return null;
    }

    static Map<String, List<Struct>> getRoleSpecificDenyPolicies(String domain) {
        try {
            ZpeClient zpeclt = getZpeClient();
            Map<String, List<Struct>> roleAsserts = zpeclt.getRoleDenyAssertions(domain);
            return roleAsserts;
        } catch (Exception exc) {
            LOG.error("getRoleSpecificDenyPolicies: exc: " + exc.getMessage());
        }
        return null;
    }
}


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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class ZTSClientTokenCacher {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSClientTokenCacher.class);

    /**
     * @deprecated use setRoleToken without the trustDomain argument instead
     * @param signedRoleToken the role token
     * @param roleName the role, can be null
     * @param trustDomain role token trust domain - not used - pass null
     */
    public static void setRoleToken(String signedRoleToken, String roleName, String trustDomain) {
        setRoleToken(signedRoleToken, roleName);
    }

    /**
     * Add the given signed role token to the zts client static cache.
     *
     * @param signedRoleToken the role token
     * @param roleName the role, can be null
     */
    public static void setRoleToken(String signedRoleToken, String roleName) {
        
        // parse domain, roles, principalName, and expiry out of the token
        
        com.yahoo.athenz.auth.token.RoleToken rt = new com.yahoo.athenz.auth.token.RoleToken(signedRoleToken);

        final String domainName = rt.getDomain();
        final String principalName = rt.getPrincipal();
        
        // parse principalName for the tenant domain and service name
        // if we have an invalid principal name then we'll just skip
        
        int index = principalName.lastIndexOf('.'); // ex: cities.burbank.mysvc
        if (index == -1) {
            return;
        }

        final String tenantDomain = principalName.substring(0, index);
        final String tenantService  = principalName.substring(index + 1);
        Long expiryTime  = rt.getExpiryTime();

        RoleToken roleToken = new RoleToken().setToken(signedRoleToken).setExpiryTime(expiryTime);

        final String key = ZTSClient.getRoleTokenCacheKey(tenantDomain, tenantService,
                domainName, roleName, null);
        
        if (LOG.isInfoEnabled()) {
            LOG.info("ZTSTokenCache: cache-add key: {} expiry: {}", key, expiryTime);
        }
        
        ZTSClient.ROLE_TOKEN_CACHE.put(key, roleToken);
    }

    /**
     * Add the given access token to the zts client static cache.
     *
     * @param accessTokenResponse the access token response object returned by ZTS
     * @param roleNames list of roles names the access token was requested for, could be null
     */
    public static void setAccessToken(AccessTokenResponse accessTokenResponse, final List<String> roleNames) {

        // skip invalid access token response

        if (accessTokenResponse == null || accessTokenResponse.getAccess_token() == null) {
            return;
        }

        // parse the access token without validating the signature

        final String tokenWithoutSignature = removeSignature(accessTokenResponse.getAccess_token());
        AccessToken accessToken;
        try {
            accessToken = new AccessToken(tokenWithoutSignature, (JwtsSigningKeyResolver) null);
        } catch (Exception ex) {
            LOG.error("ZTSTokenCache: unable to parse access token", ex);
            return;
        }

        final String domainName = accessToken.getAudience();
        final String principalName = accessToken.getClientId();

        // parse principalName for the tenant domain and service name
        // if we have an invalid principal name then we'll just skip

        int index = principalName.lastIndexOf('.');
        if (index == -1) {
            return;
        }

        final String tenantDomain = principalName.substring(0, index);
        final String tenantService  = principalName.substring(index + 1);

        AccessTokenResponseCacheEntry cacheEntry = new AccessTokenResponseCacheEntry(accessTokenResponse);

        String proxyPrincipalSpiffeUris = null;
        List<String> spiffeUris = accessToken.getConfirmProxyPrincpalSpiffeUris();
        if (spiffeUris != null) {
            proxyPrincipalSpiffeUris = String.join(",", spiffeUris);
        }

        final String idTokenServiceName = extractIdTokenServiceName(accessTokenResponse.getId_token());
        final String key = ZTSClient.getAccessTokenCacheKey(tenantDomain, tenantService,
                domainName, roleNames, idTokenServiceName, accessToken.getProxyPrincipal(),
                accessToken.getAuthorizationDetails(), proxyPrincipalSpiffeUris);

        if (LOG.isInfoEnabled()) {
            LOG.info("ZTSTokenCache: cache-add key: {} expires-in: {}", key, accessTokenResponse.getExpires_in());
        }

        ZTSClient.ACCESS_TOKEN_CACHE.put(key, cacheEntry);
    }

    private static String extractIdTokenServiceName(final String token) {

        if (token == null) {
            return null;
        }

        final String tokenWithoutSignature = removeSignature(token);
        IdToken idToken;
        try {
            idToken = new IdToken(tokenWithoutSignature, (JwtsSigningKeyResolver) null);
        } catch (Exception ex) {
            LOG.error("ZTSTokenCache: unable to parse id token", ex);
            return null;
        }

        final String fullServiceName = idToken.getAudience();
        if (fullServiceName == null) {
            LOG.error("ZTSTokenCache: token has no audience");
            return null;
        }

        int index = fullServiceName.lastIndexOf('.');
        if (index == -1) {
            LOG.error("ZTSTokenCache: invalid id token audience - {}", fullServiceName);
            return null;
        }

        return fullServiceName.substring(index + 1);
    }

    private static String removeSignature(final String accessToken) {
        int idx = accessToken.lastIndexOf('.');
        return (idx == -1) ? accessToken : accessToken.substring(0, idx + 1);
    }
}


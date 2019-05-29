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
package com.yahoo.athenz.zts;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

        String domainName    = rt.getDomain();
        String principalName = rt.getPrincipal();
        
        // parse principalName for the tenant domain and service name
        // if we have an invalid principal name then we'll just skip
        
        int index = principalName.lastIndexOf('.'); // ex: cities.burbank.mysvc
        if (index == -1) {
            return;
        }

        String tenantDomain = principalName.substring(0, index);
        String tenantService  = principalName.substring(index + 1);
        Long expiryTime  = rt.getExpiryTime();

        RoleToken roleToken = new RoleToken().setToken(signedRoleToken).setExpiryTime(expiryTime);

        String key = ZTSClient.getRoleTokenCacheKey(tenantDomain, tenantService,
                domainName, roleName, null);
        
        if (LOG.isInfoEnabled()) {
            LOG.info("ZTSTokenCache: cache-add key: {} expiry: {}", key, expiryTime);
        }
        
        ZTSClient.ROLE_TOKEN_CACHE.put(key, roleToken);
    }
}


/*
 * Copyright 2019 Oath Holdings Inc.
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

import java.util.*;

public class AccessTokenRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenRequest.class);

    public static String OBJECT_DOMAIN = ":domain";
    public static String OBJECT_ROLE   = ":role.";
    public static String OBJECT_OPENID = "openid";

    String domainName = null;
    Set<String> roleNames;
    boolean scopeResponse = false;
    boolean openidScope = false;

    public AccessTokenRequest(final String scope) {

        final String[] scopeList = scope.split(" ");

        // the format of our scopes are:
        // <domainName>:domain
        // <domainName>:role.<roleName>

        Set<String> scopeRoleNames = new HashSet<>();
        for (String scopeItem : scopeList) {

            // first check if we haven an openid scope requested

            if (OBJECT_OPENID.equalsIgnoreCase(scopeItem)) {
                openidScope = true;
                continue;
            }

            // next check if we have a domain scope

            if (scopeItem.endsWith(OBJECT_DOMAIN)) {
                final String scopeDomainName = scopeItem.substring(0, scopeItem.length() - OBJECT_DOMAIN.length());
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Multiple domains specified in scope {}", scope);
                    }
                    throw new ResourceException(ResourceException.BAD_REQUEST,
                            new ResourceError().code(ResourceException.BAD_REQUEST).message("Multiple domains in scope"));
                }
                domainName = scopeDomainName;
                scopeResponse = true;
                continue;
            }

            // finally check if we have a role scope

            int idx = scopeItem.indexOf(OBJECT_ROLE);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    LOGGER.error("Multiple domains specified in scope {}", scope);
                    throw new ResourceException(ResourceException.BAD_REQUEST,
                            new ResourceError().code(ResourceException.BAD_REQUEST).message("Multiple domains in scope"));
                }
                domainName = scopeDomainName;
                scopeRoleNames.add(scopeItem.substring(idx + OBJECT_ROLE.length()));
                continue;
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Skipping unknown scope {}", scopeItem);
            }
        }

        // if we don't have a domain then it's invalid scope

        if (domainName == null || domainName.isEmpty()) {
            LOGGER.error("No domains specified in scope {}", scope);
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    new ResourceError().code(ResourceException.BAD_REQUEST).message("No domains in scope"));
        }

        // if the scope response is set to true then we had
        // an explicit request for all roles in the domain
        // so we're going to ignore the role names requested

        if (!scopeResponse && !scopeRoleNames.isEmpty()) {
            roleNames = scopeRoleNames;
        }
    }

    public String getDomainName() {
        return domainName;
    }

    public String[] getRoleNames() {
        return roleNames == null ? null : roleNames.toArray(new String[0]);
    }

    public boolean isScopeResponse() {
        return scopeResponse;
    }

    public boolean isOpenidScope() {
        return openidScope;
    }
}

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
    private static boolean supportOpenidScope = Boolean.parseBoolean(
            System.getProperty(ZTSConsts.ZTS_PROP_OAUTH_OPENID_SCOPE, "false"));

    public static String OBJECT_DOMAIN  = ":domain";
    public static String OBJECT_ROLE    = ":role.";
    public static String OBJECT_SERVICE = ":service.";
    public static String OBJECT_OPENID  = "openid";

    String domainName = null;
    String serviceName = null;
    Set<String> roleNames;
    boolean sendScopeResponse = false;
    boolean openidScope = false;

    public AccessTokenRequest(final String scope) {

        final String[] scopeList = scope.split(" ");

        // the format of our scopes for role access token are:
        // <domainName>:domain
        // <domainName>:role.<roleName>
        // the format of our scopes for openid are:
        // openid <domainName>:service.<serviceName>

        Set<String> scopeRoleNames = new HashSet<>();
        for (String scopeItem : scopeList) {

            // first check if we haven an openid scope requested

            if (OBJECT_OPENID.equalsIgnoreCase(scopeItem)) {
                openidScope = true;
                continue;
            }

            // next check if we have a service scope required by openid

            int idx = scopeItem.indexOf(OBJECT_SERVICE);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    LOGGER.error("Multiple domains specified in scope {}", scope);
                    throw new ResourceException(ResourceException.BAD_REQUEST,
                            new ResourceError().code(ResourceException.BAD_REQUEST)
                                    .message("Multiple domains in scope"));
                }
                final String scopeServiceName = scopeItem.substring(idx + OBJECT_SERVICE.length());
                if (serviceName != null && !scopeServiceName.equals(serviceName)) {
                    LOGGER.error("Multiple domains specified in scope {}", scope);
                    throw new ResourceException(ResourceException.BAD_REQUEST,
                            new ResourceError().code(ResourceException.BAD_REQUEST)
                                    .message("Multiple services in scope"));
                }
                domainName = scopeDomainName;
                serviceName = scopeServiceName;
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
                            new ResourceError().code(ResourceException.BAD_REQUEST)
                                    .message("Multiple domains in scope"));
                }
                domainName = scopeDomainName;
                sendScopeResponse = true;
                continue;
            }

            // finally check if we have a role scope

            idx = scopeItem.indexOf(OBJECT_ROLE);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    LOGGER.error("Multiple domains specified in scope {}", scope);
                    throw new ResourceException(ResourceException.BAD_REQUEST,
                            new ResourceError().code(ResourceException.BAD_REQUEST)
                                    .message("Multiple domains in scope"));
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
                    new ResourceError().code(ResourceException.BAD_REQUEST)
                            .message("No domains in scope"));
        }

        // if the scope response is set to true then we had
        // an explicit request for all roles in the domain
        // so we're going to ignore the role names requested

        if (!sendScopeResponse && !scopeRoleNames.isEmpty()) {
            roleNames = scopeRoleNames;
        }

        // for openid scope we must have the openid scope
        // along with the service name since the audience
        // must be set for that service only

        if (openidScope && (serviceName == null || serviceName.isEmpty())) {
            LOGGER.error("No audience service name specified in openid scope {}", scope);
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    new ResourceError().code(ResourceException.BAD_REQUEST)
                            .message("No audience service name for openid scope"));
        }
    }

    public String getDomainName() {
        return domainName;
    }

    public String getServiceName() {
        return serviceName;
    }

    public String[] getRoleNames() {
        return roleNames == null ? null : roleNames.toArray(new String[0]);
    }

    public boolean sendScopeResponse() {
        return sendScopeResponse;
    }

    public boolean isOpenidScope() {
        return supportOpenidScope && openidScope;
    }

    public static void setSupportOpenidScope(boolean value) {
        supportOpenidScope = value;
    }
}

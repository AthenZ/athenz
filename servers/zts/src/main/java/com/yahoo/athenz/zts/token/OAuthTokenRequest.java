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
package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.zts.ResourceError;
import com.yahoo.athenz.zts.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

public class OAuthTokenRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthTokenRequest.class);

    public static String OBJECT_DOMAIN  = ":domain";
    public static String OBJECT_ROLE    = ":role.";
    public static String OBJECT_GROUP   = ":group.";
    public static String OBJECT_SERVICE = ":service.";
    public static String OBJECT_OPENID  = "openid";
    public static String OBJECT_GROUPS  = "groups";
    public static String OBJECT_ROLES   = "roles";

    String domainName = null;
    String serviceName = null;
    Set<String> roleNames;
    Set<String> groupNames;
    boolean sendScopeResponse = false;
    boolean openIdScope = false;
    boolean groupsScope = false;
    boolean rolesScope = false;

    public OAuthTokenRequest(final String scope) {

        final String[] scopeList = scope.split(" ");

        // the format of our scopes for role access token and id tokens are:
        // access token/id token combo:
        //   <domainName>:domain
        //   <domainName>:role.<roleName>
        //   openid <domainName>:service.<serviceName>
        // id token requests (service is required uri client_id parameter):
        //   openid
        //   openid [groups | roles]
        //   openid <domainName>:role.<roleName>
        //   openid <domainName>:group.<groupName>

        Set<String> scopeRoleNames = new HashSet<>();
        Set<String> scopeGroupNames = new HashSet<>();
        for (String scopeItem : scopeList) {

            // first check if we have an openid scope requested

            if (OBJECT_OPENID.equalsIgnoreCase(scopeItem)) {
                openIdScope = true;
                continue;
            } else if (OBJECT_GROUPS.equalsIgnoreCase(scopeItem)) {
                groupsScope = true;
                continue;
            } else if (OBJECT_ROLES.equalsIgnoreCase(scopeItem)) {
                rolesScope = true;
                continue;
            }

            // next check if we have a service scope required by openid

            int idx = scopeItem.indexOf(OBJECT_SERVICE);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                if (scopeDomainName.isEmpty()) {
                    throw error("Service name without domain name", scope);
                }
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    throw error("Multiple domains in scope", scope);
                }
                final String scopeServiceName = scopeItem.substring(idx + OBJECT_SERVICE.length());
                if (serviceName != null && !scopeServiceName.equals(serviceName)) {
                    throw error("Multiple services in scope", scope);
                }
                domainName = scopeDomainName;
                serviceName = scopeServiceName;
                continue;
            }

            // next check if we have a domain scope

            if (scopeItem.endsWith(OBJECT_DOMAIN)) {
                final String scopeDomainName = scopeItem.substring(0, scopeItem.length() - OBJECT_DOMAIN.length());
                if (scopeDomainName.isEmpty()) {
                    throw error("Domain scope name without domain name", scope);
                }
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    throw error("Multiple domains in scope", scope);
                }
                domainName = scopeDomainName;
                sendScopeResponse = true;
                continue;
            }

            // next check if we have a role scope

            idx = scopeItem.indexOf(OBJECT_ROLE);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                if (scopeDomainName.isEmpty()) {
                    throw error("Role name without domain name", scope);
                }
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    throw error("Multiple domains in scope", scope);
                }
                domainName = scopeDomainName;
                scopeRoleNames.add(scopeItem.substring(idx + OBJECT_ROLE.length()));
                continue;
            }

            // finally, check if we have a group scope

            idx = scopeItem.indexOf(OBJECT_GROUP);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                if (scopeDomainName.isEmpty()) {
                    throw error("Group name without domain name", scope);
                }
                if (domainName != null && !scopeDomainName.equals(domainName)) {
                    throw error("Multiple domains in scope", scope);
                }
                domainName = scopeDomainName;
                scopeGroupNames.add(scopeItem.substring(idx + OBJECT_GROUP.length()));
                continue;
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Skipping unknown scope {}", scopeItem);
            }
        }

        // if the scope response is set to true then we had
        // an explicit request for all roles or groups in the domain
        // then we're going to ignore the role and groups names requested,
        // but we still need to set the role/group scope in case
        // some role or group name was passed without the explicit scope

        if (!sendScopeResponse) {
            if (!scopeRoleNames.isEmpty()) {
                roleNames = scopeRoleNames;
            }
            if (!scopeGroupNames.isEmpty()) {
                groupNames = scopeGroupNames;
            }
        } else {
            if (!scopeRoleNames.isEmpty()) {
                rolesScope = true;
            }
            if (!scopeGroupNames.isEmpty()) {
                groupsScope = true;
            }
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

    public Set<String> getGroupNames() {
        return groupNames;
    }

    public boolean sendScopeResponse() {
        return sendScopeResponse;
    }

    public boolean isOpenIdScope() {
        return openIdScope;
    }

    public boolean isGroupsScope() {
        return groupsScope;
    }

    public boolean isRolesScope() {
        return rolesScope;
    }

    ResourceException error(final String message, final String scope) {
        LOGGER.error("access token request error: {} - {}", message, scope);
        return new ResourceException(ResourceException.BAD_REQUEST,
                new ResourceError().code(ResourceException.BAD_REQUEST).message(message));
    }
}

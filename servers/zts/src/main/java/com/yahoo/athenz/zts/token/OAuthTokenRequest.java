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

import java.util.*;

public class OAuthTokenRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthTokenRequest.class);

    public static String OBJECT_DOMAIN  = ":domain";
    public static String OBJECT_ROLE    = ":role.";
    public static String OBJECT_GROUP   = ":group.";
    public static String OBJECT_SERVICE = ":service.";
    public static String OBJECT_OPENID  = "openid";
    public static String OBJECT_GROUPS  = "groups";
    public static String OBJECT_ROLES   = "roles";

    Set<String> domainNames = new HashSet<>();
    String serviceName = null;
    Map<String, Set<String>> roleNames;
    Map<String, Set<String>> groupNames;
    boolean sendScopeResponse = false;
    boolean openIdScope = false;
    boolean groupsScope = false;
    boolean rolesScope = false;
    int maxDomains;

    public OAuthTokenRequest(final String scope, int maxDomains) {

        this.maxDomains = maxDomains;
        if (this.maxDomains < 1) {
            throw error("Invalid value specified for max domains", scope);
        }
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
        //   openid [<domainName>:domain]+

        Map<String, Set<String>> scopeRoleNames = new HashMap<>();
        Map<String, Set<String>> scopeGroupNames = new HashMap<>();
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
                addScopeDomain(scopeDomainName, scope);
                final String scopeServiceName = scopeItem.substring(idx + OBJECT_SERVICE.length());
                if (serviceName != null && !scopeServiceName.equals(serviceName)) {
                    throw error("Multiple services in scope", scope);
                }
                serviceName = scopeServiceName;
                continue;
            }

            // next check if we have a domain scope

            if (scopeItem.endsWith(OBJECT_DOMAIN)) {
                final String scopeDomainName = scopeItem.substring(0, scopeItem.length() - OBJECT_DOMAIN.length());
                addScopeDomain(scopeDomainName, scope);
                sendScopeResponse = true;
                continue;
            }

            // next check if we have a role scope

            idx = scopeItem.indexOf(OBJECT_ROLE);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                addScopeDomain(scopeDomainName, scope);
                scopeRoleNames.putIfAbsent(scopeDomainName, new HashSet<>());
                scopeRoleNames.get(scopeDomainName).add(scopeItem.substring(idx + OBJECT_ROLE.length()));
                continue;
            }

            // finally, check if we have a group scope

            idx = scopeItem.indexOf(OBJECT_GROUP);
            if (idx != -1) {
                final String scopeDomainName = scopeItem.substring(0, idx);
                addScopeDomain(scopeDomainName, scope);
                scopeGroupNames.putIfAbsent(scopeDomainName, new HashSet<>());
                scopeGroupNames.get(scopeDomainName).add(scopeItem.substring(idx + OBJECT_GROUP.length()));
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
        return (maxDomains == 1 && !domainNames.isEmpty()) ? domainNames.stream().findFirst().get() : null;
    }

    public Set<String> getDomainNames() {
        return domainNames;
    }

    public String getServiceName() {
        return serviceName;
    }

    public String[] getRoleNames(final String domainName) {
        if (roleNames == null) {
            return null;
        }
        Set<String> domainRoleNames = roleNames.get(domainName);
        return domainRoleNames == null ? null : domainRoleNames.toArray(new String[0]);
    }

    public Set<String> getGroupNames(final String domainName) {
        if (groupNames == null) {
            return null;
        }
        return groupNames.get(domainName);
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

    void addScopeDomain(final String scopeDomainName, final String scope) {
        if (scopeDomainName.isEmpty()) {
            throw error("empty domain name", scope);
        }
        final String domainName = getDomainName();
        if (domainName != null && !scopeDomainName.equals(domainName)) {
             throw error("Multiple domains in scope", scope);
        }
        if (!domainNames.contains(scopeDomainName)) {
            if (domainNames.size() == maxDomains) {
                throw error("Domain limit: " + maxDomains + " has been reached", scope);
            }
            domainNames.add(scopeDomainName);
        }
    }

    ResourceException error(final String message, final String scope) {
        LOGGER.error("oauth token request error: {} - {}", message, scope);
        return new ResourceException(ResourceException.BAD_REQUEST,
                new ResourceError().code(ResourceException.BAD_REQUEST).message(message));
    }
}

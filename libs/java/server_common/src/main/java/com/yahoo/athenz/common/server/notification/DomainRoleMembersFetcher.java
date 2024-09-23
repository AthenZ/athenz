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

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.common.server.db.RolesProvider;

import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

public class DomainRoleMembersFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(DomainRoleMembersFetcher.class);

    private final RolesProvider rolesProvider;
    private final DomainRoleMembersFetcherCommon domainRoleMembersFetcherCommon;

    public DomainRoleMembersFetcher(RolesProvider rolesProvider, String userDomainPrefix) {
        this.rolesProvider = rolesProvider;
        this.domainRoleMembersFetcherCommon = new DomainRoleMembersFetcherCommon(userDomainPrefix);
    }

    public Set<String> getDomainRoleMembers(String domainName, String roleName) {

        if (rolesProvider == null) {
            return new HashSet<>();
        }

        // we're going to use our new getRole interface api to get the
        // role fully expanded with all its members. However, if the
        // provider does not support this interface then we're going
        // fall back to the old method of getting the role members

        // if our given role name is the full arn, so first we need to
        // extract the local role component from the role name

        String roleLocalName;
        int idx = roleName.indexOf(AuthorityConsts.ROLE_SEP);
        if (idx == -1) {
            roleLocalName = roleName;
        } else {
            roleLocalName = roleName.substring(idx + AuthorityConsts.ROLE_SEP.length());
        }

        try {
            Role role = rolesProvider.getRole(domainName, roleLocalName, Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
            if (role != null) {
                return domainRoleMembersFetcherCommon.getDomainRoleMembers(role);
            }
        } catch (Exception ex) {
            if (ex instanceof UnsupportedOperationException) {
                String roleFullName;
                if (idx == -1) {
                    roleFullName = ResourceUtils.roleResourceName(domainName, roleName);
                } else {
                    roleFullName = roleName;
                }
                return domainRoleMembersFetcherCommon.getDomainRoleMembers(roleFullName,
                        rolesProvider.getRolesByDomain(domainName));
            }
            LOGGER.error("unable to fetch members for role: {} in domain: {} error: {}",
                    roleName, domainName, ex.getMessage(), ex);
        }
        return new HashSet<>();
    }
}

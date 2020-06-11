/*
 * Copyright 2020 Verizon Media
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

import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.zms.Role;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DomainRoleMembersFetcher {
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

        List<Role> roles = rolesProvider.getRolesByDomain(domainName);
        if (roles == null) {
            return new HashSet<>();
        }

        return domainRoleMembersFetcherCommon.getDomainRoleMembers(roleName, roles);
    }
}

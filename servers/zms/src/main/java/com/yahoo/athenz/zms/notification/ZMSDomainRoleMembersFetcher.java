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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcher;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.store.AthenzDomain;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class ZMSDomainRoleMembersFetcher implements DomainRoleMembersFetcher {
    private final DBService dbService;
    private final String userDomainPrefix;

    public ZMSDomainRoleMembersFetcher(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
    }

    @Override
    public Set<String> getDomainRoleMembers(String domainName, String roleName) {
        AthenzDomain domain = dbService.getAthenzDomain(domainName, false);
        if (domain == null || domain.getRoles() == null) {
            return new HashSet<>();
        }

        for (Role role : domain.getRoles()) {
            if (role.getName().equals(roleName)) {
                return role.getRoleMembers().stream()
                        .filter(this::isUnexpiredUser)
                        .map(RoleMember::getMemberName).collect(Collectors.toSet());
            }
        }

        return new HashSet<>();
    }

    private boolean isUnexpiredUser(RoleMember roleMember) {
        if (!roleMember.getMemberName().startsWith(userDomainPrefix)) {
            return false;
        }

        return (roleMember.getExpiration() == null) || (roleMember.getExpiration().millis() > System.currentTimeMillis());
    }
}

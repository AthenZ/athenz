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

import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class DomainRoleMembersFetcherCommon {
    private final String userDomainPrefix;

    public DomainRoleMembersFetcherCommon(String userDomainPrefix) {
        this.userDomainPrefix = userDomainPrefix;
    }

    public Set<String> getDomainRoleMembers(Role role) {

        if (role.getRoleMembers() == null) {
            return new HashSet<>();
        }

        return role.getRoleMembers().stream()
                .filter(this::isUnexpiredUser)
                .map(RoleMember::getMemberName).collect(Collectors.toSet());
    }

    public Set<String> getDomainRoleMembers(String roleName, List<Role> roles) {

        if (roles == null) {
            return new HashSet<>();
        }

        for (Role role : roles) {
            if (role.getName() == null) {
                continue;
            }

            if (role.getName().equals(roleName)) {
                return getDomainRoleMembers(role);
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

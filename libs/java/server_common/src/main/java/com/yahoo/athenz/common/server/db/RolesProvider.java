/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.db;

import com.yahoo.athenz.zms.Role;
import java.util.List;
import java.util.Set;

/**
 * A common interface used by ZMS and ZTS for providing roles by domain
 */
public interface RolesProvider {

    /**
     * Return the full list of roles from the given domain
     * @param domainName name of the domain
     * @return List of roles from the domain
     */
    List<Role> getRolesByDomain(String domainName);

    /**
     * Return the requested role from the given domain. If the
     * expand flag is set to true, the provider will automatically
     * expand the role members and return the full list of members
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param auditLog flag to indicate to return audit log entries
     * @param expand flag to indicate to expand group and delegated role membership
     * @param pending flag to indicate to return pending members
     * @return the role object from the given domain
     */
    default Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand, Boolean pending) {
        throw new UnsupportedOperationException();
    }

    /**
     * Return a set of roles from the given domain that have
     * the requested principal as a member
     * @param domainName name of the domain
     * @param principal name of the principal to look for
     * @return a set of roles that have the principal as a member
     */
    default Set<String> getRolesForPrincipal(String domainName, String principal) {
        throw new UnsupportedOperationException();
    }
}

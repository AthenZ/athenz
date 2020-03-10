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
import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcherCommon;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.store.AthenzDomain;

import java.util.HashSet;
import java.util.Set;

public class ZMSDomainRoleMembersFetcher implements DomainRoleMembersFetcher {
    private final DBService dbService;
    private final DomainRoleMembersFetcherCommon domainRoleMembersFetcherCommon;

    public ZMSDomainRoleMembersFetcher(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        this.domainRoleMembersFetcherCommon = new DomainRoleMembersFetcherCommon(userDomainPrefix);
    }

    @Override
    public Set<String> getDomainRoleMembers(String domainName, String roleName) {
        if (dbService == null) {
            return new HashSet<>();
        }

        AthenzDomain domain = dbService.getAthenzDomain(domainName, false);
        if (domain == null) {
            return new HashSet<>();
        }

        return domainRoleMembersFetcherCommon.getDomainRoleMembers(roleName, domain.getRoles());
    }
}

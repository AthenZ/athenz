/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcher;
import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcherCommon;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zts.store.DataStore;

import java.util.HashSet;
import java.util.Set;

public class ZTSDomainRoleMembersFetcher implements DomainRoleMembersFetcher {

    private final DataStore dataStore;
    private final DomainRoleMembersFetcherCommon domainRoleMembersFetcherCommon;

    public ZTSDomainRoleMembersFetcher(DataStore dataStore, String userDomainPrefix) {
        this.dataStore = dataStore;
        this.domainRoleMembersFetcherCommon = new DomainRoleMembersFetcherCommon(userDomainPrefix);
    }

    @Override
    public Set<String> getDomainRoleMembers(String domainName, String roleName) {
        if (dataStore == null) {
            return new HashSet<>();
        }

        DomainData domainData = dataStore.getDomainData(domainName);
        if (domainData == null) {
            return new HashSet<>();
        }

        return domainRoleMembersFetcherCommon.getDomainRoleMembers(roleName, domainData.getRoles());
    }
}

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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.notification.DomainRoleMembersFetcher;
import com.yahoo.athenz.zts.store.DataStore;
import org.testng.annotations.Test;

import java.util.HashSet;
import java.util.Set;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static org.mockito.Mockito.mock;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class DomainRoleMembersFetcherTest {
    @Test
    public void testGetDomainRoleMembers() {
        DataStore dataStore = mock(DataStore.class);
        NotificationTestsCommon.mockDomainData(1, dataStore);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(
                dataStore,
                USER_DOMAIN_PREFIX);

        Set<String> domainRoleMembers = domainRoleMembersFetcher.getDomainRoleMembers(
                "domain1",
                "domain1:role.admin");

        assertEquals(2, domainRoleMembers.size());
        assertTrue(domainRoleMembers.contains("user.domain1rolemember1"));
        assertTrue(domainRoleMembers.contains("user.domain1rolemember2"));
    }

    @Test
    public void testNoDataStore() {
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(
                null,
                USER_DOMAIN_PREFIX);

        Set<String> domainRoleMembers = domainRoleMembersFetcher.getDomainRoleMembers(
                "domain1",
                "domain1:role.admin");

        assertEquals(new HashSet<>(), domainRoleMembers);
    }

    @Test
    public void testNoDomain() {
        DataStore dataStore = mock(DataStore.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(
                dataStore,
                USER_DOMAIN_PREFIX);

        Set<String> domainRoleMembers = domainRoleMembersFetcher.getDomainRoleMembers(
                "domain1",
                "domain1:role.admin");

        assertEquals(new HashSet<>(), domainRoleMembers);
    }
}

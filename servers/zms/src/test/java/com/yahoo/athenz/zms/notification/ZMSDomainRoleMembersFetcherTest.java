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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class ZMSDomainRoleMembersFetcherTest {
    @Test
    public void testGetDomainRoleMembers() {
        DBService dbsvc = Mockito.mock(DBService.class);

        String domainName = "domain1";
        AthenzDomain domainData = new AthenzDomain(domainName);
        Role adminRole = new Role();
        adminRole.setName(domainName + ":role.admin");
        RoleMember roleMember1 = new RoleMember();
        roleMember1.setMemberName("user.domain1rolemember1");
        RoleMember roleMember2 = new RoleMember();
        roleMember2.setMemberName("user.domain1rolemember2");
        adminRole.setRoleMembers(Arrays.asList(roleMember1, roleMember2));
        domainData.setRoles(Collections.singletonList(adminRole));
        Mockito.when(dbsvc.getAthenzDomain(eq("domain1"), anyBoolean())).thenReturn(domainData);

        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(
                dbsvc,
                USER_DOMAIN_PREFIX);

        Set<String> domainRoleMembers = zmsDomainRoleMembersFetcher.getDomainRoleMembers(
                "domain1",
                "domain1:role.admin");

        assertEquals(2, domainRoleMembers.size());
        assertTrue(domainRoleMembers.contains("user.domain1rolemember1"));
        assertTrue(domainRoleMembers.contains("user.domain1rolemember2"));
    }

    @Test
    public void testNoDataStore() {
        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(
                null,
                USER_DOMAIN_PREFIX);

        Set<String> domainRoleMembers = zmsDomainRoleMembersFetcher.getDomainRoleMembers(
                "domain1",
                "domain1:role.admin");

        assertEquals(new HashSet<>(), domainRoleMembers);
    }

    @Test
    public void testNoDomain() {
        DBService dbsvc = Mockito.mock(DBService.class);
        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(
                dbsvc,
                USER_DOMAIN_PREFIX);

        Set<String> domainRoleMembers = zmsDomainRoleMembersFetcher.getDomainRoleMembers(
                "domain1",
                "domain1:role.admin");

        assertEquals(new HashSet<>(), domainRoleMembers);
    }
}

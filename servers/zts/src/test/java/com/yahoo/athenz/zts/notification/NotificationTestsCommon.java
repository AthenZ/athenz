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

import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zts.store.DataStore;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.eq;

public class NotificationTestsCommon {
    public static void mockDomainData(int i, DataStore dataStore) {
        String domainName = "domain" + i;
        Role adminRole = new Role();
        adminRole.setName(domainName + ":role.admin");
        RoleMember roleMember1 = new RoleMember();
        roleMember1.setMemberName("user.domain" + i + "rolemember1");
        RoleMember roleMember2 = new RoleMember();
        roleMember2.setMemberName("user.domain" + i + "rolemember2");
        adminRole.setRoleMembers(Arrays.asList(roleMember1, roleMember2));
        Mockito.when(dataStore.getRolesByDomain(eq(domainName))).thenReturn(Collections.singletonList(adminRole));
        Mockito.when(dataStore.getRole(domainName, "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenThrow(new UnsupportedOperationException());
    }
}

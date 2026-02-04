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
package com.yahoo.athenz.common.server.store.impl;

import com.yahoo.athenz.common.server.store.PrincipalRole;
import com.yahoo.athenz.zms.*;
import org.testng.annotations.Test;


import static org.testng.Assert.*;

public class PrincipalRoleTest {

    @Test
    public void testPrincipalRole() {

        PrincipalRole role = new PrincipalRole();
        assertNull(role.getDomainName());
        assertNull(role.getRoleName());
        assertNull(role.getDomainUserAuthorityFilter());
        assertEquals(role.getDomainMemberExpiryDays(), 0);

        role.setDomainName("domain");
        role.setRoleName("role");
        role.setDomainUserAuthorityFilter("filter");
        role.setDomainMemberExpiryDays(10);

        assertEquals(role.getDomainName(), "domain");
        assertEquals(role.getRoleName(), "role");
        assertEquals(role.getDomainUserAuthorityFilter(), "filter");
        assertEquals(role.getDomainMemberExpiryDays(), 10);
    }
}

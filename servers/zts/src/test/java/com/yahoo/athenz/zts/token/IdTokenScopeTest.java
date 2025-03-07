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
package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.zts.ResourceException;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class IdTokenScopeTest {

    @Test
    public void testIdTokenScope() {

        //   openid
        //   openid [groups | roles]
        //   openid <domainName>:role.<roleName>
        //   openid <domainName>:group.<groupName>

        IdTokenScope.setMaxDomains(1);

        IdTokenScope req1 = new IdTokenScope("openid");
        assertNotNull(req1);
        assertNull(req1.getDomainName());
        assertNull(req1.getRoleNames("sports"));
        assertNull(req1.getGroupNames("sports"));
        assertTrue(req1.isOpenIdScope());
        assertFalse(req1.isGroupsScope());
        assertFalse(req1.isRolesScope());

        IdTokenScope req2 = new IdTokenScope("openid groups");
        assertNotNull(req2);
        assertNull(req2.getDomainName());
        assertNull(req2.getRoleNames("sports"));
        assertNull(req2.getGroupNames("sports"));
        assertTrue(req2.isOpenIdScope());
        assertTrue(req2.isGroupsScope());
        assertFalse(req2.isRolesScope());

        IdTokenScope req3 = new IdTokenScope("openid roles");
        assertNotNull(req3);
        assertNull(req3.getDomainName());
        assertNull(req3.getRoleNames("sports"));
        assertNull(req3.getGroupNames("sports"));
        assertTrue(req3.isOpenIdScope());
        assertFalse(req3.isGroupsScope());
        assertTrue(req3.isRolesScope());

        IdTokenScope req4 = new IdTokenScope("openid sports:group.dev-team");
        assertNotNull(req4);
        assertEquals(req4.getDomainName(), "sports");
        assertNull(req4.getRoleNames("sports"));
        assertEquals(req4.getGroupNames("sports").size(), 1);
        assertTrue(req4.getGroupNames("sports").contains("dev-team"));
        assertTrue(req4.isOpenIdScope());
        assertTrue(req4.isGroupsScope());
        assertFalse(req4.isRolesScope());

        IdTokenScope req5 = new IdTokenScope("openid sports:role.dev-role");
        assertNotNull(req5);
        assertEquals(req5.getDomainName(), "sports");
        assertEquals(req5.getRoleNames("sports").length, 1);
        assertEquals(req5.getRoleNames("sports")[0], "dev-role");
        assertNull(req5.getGroupNames("sports"));
        assertTrue(req5.isOpenIdScope());
        assertFalse(req5.isGroupsScope());
        assertTrue(req5.isRolesScope());

        IdTokenScope req6 = new IdTokenScope("openid sports:service.api sports:domain sports:group.dev-team");
        assertNotNull(req6);
        assertEquals(req6.getDomainName(), "sports");
        assertNull(req6.getRoleNames("sports"));
        assertNull(req6.getGroupNames("sports"));
        assertTrue(req6.sendScopeResponse());
        assertTrue(req6.isOpenIdScope());
        assertTrue(req6.isGroupsScope());
        assertFalse(req6.isRolesScope());

        IdTokenScope req7 = new IdTokenScope("openid sports:service.api sports:role.reader sports:group.dev-team");
        assertNotNull(req7);
        assertEquals(req7.getDomainName(), "sports");
        assertEquals(req7.getRoleNames("sports").length, 1);
        assertEquals(req7.getRoleNames("sports")[0], "reader");
        assertEquals(req7.getGroupNames("sports").size(), 1);
        assertTrue(req7.getGroupNames("sports").contains("dev-team"));
        assertFalse(req7.sendScopeResponse());
        assertTrue(req7.isOpenIdScope());
        assertTrue(req7.isGroupsScope());
        assertTrue(req7.isRolesScope());

        IdTokenScope req8 = new IdTokenScope("openid groups unknown-scope");
        assertNotNull(req8);
        assertNull(req8.getDomainName());
        assertNull(req8.getRoleNames("sports"));
        assertNull(req8.getGroupNames("sports"));
        assertTrue(req8.isOpenIdScope());
        assertTrue(req8.isGroupsScope());
        assertFalse(req8.isRolesScope());
        assertFalse(req7.sendScopeResponse());
    }

    @Test
    public void testIdTokenScopeNoOpenid() {

        IdTokenScope.setMaxDomains(1);

        try {
            new IdTokenScope("groups");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("unknown-scope");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope(":role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("sports:role.role1 :role.role2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("openid sports:group.dev-team :group.prod-team");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("openid :group.prod-team");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("sports:role.role1 openid weather:service.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("sports:group.dev-team openid weather:group.dev-team");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("sports:role.role1 openid sports:service.api sports:service.backend");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testIdTokenScopeMultipleDomains() {

        IdTokenScope.setMaxDomains(1);

        IdTokenScope req1 = new IdTokenScope("openid sports:domain sports:domain");
        assertNotNull(req1);

        try {
            new IdTokenScope("openid sports:domain weather:domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("openid sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new IdTokenScope("openid weather:role.role2 sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
}

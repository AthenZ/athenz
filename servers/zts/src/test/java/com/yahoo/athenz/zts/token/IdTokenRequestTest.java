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
import static org.testng.AssertJUnit.assertEquals;

public class IdTokenRequestTest {

    @Test
    public void testIdTokenRequest() {

        //   openid
        //   openid [groups | roles]
        //   openid <domainName>:role.<roleName>
        //   openid <domainName>:group.<groupName>

        IdTokenRequest.setMaxDomains(1);

        IdTokenRequest req1 = new IdTokenRequest("openid");
        assertNotNull(req1);
        assertNull(req1.getDomainName());
        assertNull(req1.getRoleNames("sports"));
        assertNull(req1.getGroupNames("sports"));
        assertTrue(req1.isOpenIdScope());
        assertFalse(req1.isGroupsScope());
        assertFalse(req1.isRolesScope());

        IdTokenRequest req2 = new IdTokenRequest("openid groups");
        assertNotNull(req2);
        assertNull(req2.getDomainName());
        assertNull(req2.getRoleNames("sports"));
        assertNull(req2.getGroupNames("sports"));
        assertTrue(req2.isOpenIdScope());
        assertTrue(req2.isGroupsScope());
        assertFalse(req2.isRolesScope());

        IdTokenRequest req3 = new IdTokenRequest("openid roles");
        assertNotNull(req3);
        assertNull(req3.getDomainName());
        assertNull(req3.getRoleNames("sports"));
        assertNull(req3.getGroupNames("sports"));
        assertTrue(req3.isOpenIdScope());
        assertFalse(req3.isGroupsScope());
        assertTrue(req3.isRolesScope());

        IdTokenRequest req4 = new IdTokenRequest("openid sports:group.dev-team");
        assertNotNull(req4);
        assertEquals("sports", req4.getDomainName());
        assertNull(req4.getRoleNames("sports"));
        assertEquals(1, req4.getGroupNames("sports").size());
        assertTrue(req4.getGroupNames("sports").contains("dev-team"));
        assertTrue(req4.isOpenIdScope());
        assertTrue(req4.isGroupsScope());
        assertFalse(req4.isRolesScope());

        IdTokenRequest req5 = new IdTokenRequest("openid sports:role.dev-role");
        assertNotNull(req5);
        assertEquals("sports", req5.getDomainName());
        assertEquals(1, req5.getRoleNames("sports").length);
        assertEquals("dev-role", req5.getRoleNames("sports")[0]);
        assertNull(req5.getGroupNames("sports"));
        assertTrue(req5.isOpenIdScope());
        assertFalse(req5.isGroupsScope());
        assertTrue(req5.isRolesScope());

        IdTokenRequest req6 = new IdTokenRequest("openid sports:service.api sports:domain sports:group.dev-team");
        assertNotNull(req6);
        assertEquals("sports", req6.getDomainName());
        assertNull(req6.getRoleNames("sports"));
        assertNull(req6.getGroupNames("sports"));
        assertTrue(req6.sendScopeResponse());
        assertTrue(req6.isOpenIdScope());
        assertTrue(req6.isGroupsScope());
        assertFalse(req6.isRolesScope());

        IdTokenRequest req7 = new IdTokenRequest("openid sports:service.api sports:role.reader sports:group.dev-team");
        assertNotNull(req7);
        assertEquals("sports", req7.getDomainName());
        assertEquals(1, req7.getRoleNames("sports").length);
        assertEquals("reader", req7.getRoleNames("sports")[0]);
        assertEquals(1, req7.getGroupNames("sports").size());
        assertTrue(req7.getGroupNames("sports").contains("dev-team"));
        assertFalse(req7.sendScopeResponse());
        assertTrue(req7.isOpenIdScope());
        assertTrue(req7.isGroupsScope());
        assertTrue(req7.isRolesScope());

        IdTokenRequest req8 = new IdTokenRequest("openid groups unknown-scope");
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
    public void testIdTokenRequestNoOpenid() {

        IdTokenRequest.setMaxDomains(1);

        try {
            new IdTokenRequest("groups");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("unknown-scope");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest(":role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("sports:role.role1 :role.role2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("openid sports:group.dev-team :group.prod-team");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("openid :group.prod-team");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("sports:role.role1 openid weather:service.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("sports:group.dev-team openid weather:group.dev-team");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("sports:role.role1 openid sports:service.api sports:service.backend");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testIdTokenRequestMultipleDomains() {

        IdTokenRequest.setMaxDomains(1);

        IdTokenRequest req1 = new IdTokenRequest("openid sports:domain sports:domain");
        assertNotNull(req1);

        try {
            new IdTokenRequest("openid sports:domain weather:domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("openid sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new IdTokenRequest("openid weather:role.role2 sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }
}

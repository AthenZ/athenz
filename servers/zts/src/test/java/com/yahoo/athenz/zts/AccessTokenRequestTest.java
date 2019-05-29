/*
 * Copyright 2019 Oath Holdings, Inc.
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
package com.yahoo.athenz.zts;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertEquals;

public class AccessTokenRequestTest {

    @BeforeMethod
    public void setup() {
        AccessTokenRequest.setSupportOpenidScope(true);
    }

    @Test
    public void testAccessTokenRequest() {

        AccessTokenRequest req1 = new AccessTokenRequest("sports:domain");
        assertNotNull(req1);
        assertEquals("sports", req1.getDomainName());
        assertNull(req1.getRoleNames());
        assertTrue(req1.sendScopeResponse());
        assertFalse(req1.isOpenidScope());

        AccessTokenRequest req2 = new AccessTokenRequest("openid sports:service.api sports:domain");
        assertNotNull(req2);
        assertEquals("sports", req2.getDomainName());
        assertNull(req2.getRoleNames());
        assertTrue(req2.sendScopeResponse());
        assertTrue(req2.isOpenidScope());

        // due to domain scope the role name one is ignored

        AccessTokenRequest req3 = new AccessTokenRequest("openid sports:service.api sports:domain sports:role.role1");
        assertNotNull(req3);
        assertEquals("sports", req3.getDomainName());
        assertNull(req3.getRoleNames());
        assertTrue(req3.sendScopeResponse());
        assertTrue(req3.isOpenidScope());

        AccessTokenRequest req4 = new AccessTokenRequest("sports:role.role1");
        assertNotNull(req4);
        assertEquals("sports", req4.getDomainName());
        assertNotNull(req4.getRoleNames());
        assertEquals(1, req4.getRoleNames().length);
        assertEquals("role1", req4.getRoleNames()[0]);
        assertFalse(req4.sendScopeResponse());
        assertFalse(req4.isOpenidScope());

        AccessTokenRequest req5 = new AccessTokenRequest("sports:role.role1 unknown-scope");
        assertNotNull(req5);
        assertEquals("sports", req5.getDomainName());
        assertNotNull(req5.getRoleNames());
        assertEquals(1, req5.getRoleNames().length);
        assertEquals("role1", req5.getRoleNames()[0]);
        assertFalse(req5.sendScopeResponse());
        assertFalse(req5.isOpenidScope());

        AccessTokenRequest req6 = new AccessTokenRequest("sports:role.role1 sports:role.role2");
        assertNotNull(req6);
        assertEquals("sports", req6.getDomainName());
        assertNotNull(req6.getRoleNames());
        assertEquals(2, req6.getRoleNames().length);
        assertEquals("role1", req6.getRoleNames()[0]);
        assertEquals("role2", req6.getRoleNames()[1]);
        assertFalse(req6.sendScopeResponse());
        assertFalse(req6.isOpenidScope());
    }

    @Test
    public void testAccessTokenRequestOpenidDisabled() {

        AccessTokenRequest.setSupportOpenidScope(false);

        AccessTokenRequest req1 = new AccessTokenRequest("openid sports:service.api sports:domain");
        assertNotNull(req1);
        assertEquals("sports", req1.getDomainName());
        assertNull(req1.getRoleNames());
        assertTrue(req1.sendScopeResponse());
        assertFalse(req1.isOpenidScope());
    }

    @Test
    public void testAccessTokenRequestInvalidDomains() {

        try {
            new AccessTokenRequest("openid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("unknown-scope");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest(":role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("sports:role.role1 :role.role2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("sports:role.role1 openid weather:service.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("sports:role.role1 openid sports:service.api sports:service.backend");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testAccessTokenRequestNoOpenidService() {

        try {
            new AccessTokenRequest("sports:domain openid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("sports:domain openid sports:service.");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testAccessTokenRequestMultipleDomains() {

        AccessTokenRequest req1 = new AccessTokenRequest("sports:domain sports:domain");
        assertNotNull(req1);

        try {
            new AccessTokenRequest("sports:domain weather:domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            new AccessTokenRequest("weather:role.role2 sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }
}

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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AccessTokenRequestTest {

    @BeforeMethod
    public void setup() {
        AccessTokenScope.setSupportOpenIdScope(true);
    }

    @Test
    public void testAccessTokenRequest() {

        AccessTokenScope req1 = new AccessTokenScope("sports:domain");
        assertNotNull(req1);
        assertEquals(req1.getDomainName(), "sports");
        assertNull(req1.getRoleNames("sports"));
        assertTrue(req1.sendScopeResponse());
        assertFalse(req1.isOpenIdScope());

        AccessTokenScope req2 = new AccessTokenScope("openid sports:service.api sports:domain");
        assertNotNull(req2);
        assertEquals(req2.getDomainName(), "sports");
        assertNull(req2.getRoleNames("sports"));
        assertTrue(req2.sendScopeResponse());
        assertTrue(req2.isOpenIdScope());

        // due to domain scope the role name one is ignored

        AccessTokenScope req3 = new AccessTokenScope("openid sports:service.api sports:domain sports:role.role1");
        assertNotNull(req3);
        assertEquals(req3.getDomainName(), "sports");
        assertNull(req3.getRoleNames("sports"));
        assertTrue(req3.sendScopeResponse());
        assertTrue(req3.isOpenIdScope());

        AccessTokenScope req4 = new AccessTokenScope("sports:role.role1");
        assertNotNull(req4);
        assertEquals(req4.getDomainName(), "sports");
        assertNotNull(req4.getRoleNames("sports"));
        assertEquals(req4.getRoleNames("sports").length, 1);
        assertEquals(req4.getRoleNames("sports")[0], "role1");
        assertFalse(req4.sendScopeResponse());
        assertFalse(req4.isOpenIdScope());

        AccessTokenScope req5 = new AccessTokenScope("sports:role.role1 unknown-scope");
        assertNotNull(req5);
        assertEquals(req5.getDomainName(), "sports");
        assertNotNull(req5.getRoleNames("sports"));
        assertEquals(req5.getRoleNames("sports").length, 1);
        assertEquals(req5.getRoleNames("sports")[0], "role1");
        assertFalse(req5.sendScopeResponse());
        assertFalse(req5.isOpenIdScope());

        AccessTokenScope req6 = new AccessTokenScope("sports:role.role1 sports:role.role2");
        assertNotNull(req6);
        assertEquals(req6.getDomainName(), "sports");
        assertNotNull(req6.getRoleNames("sports"));
        assertEquals(req6.getRoleNames("sports").length, 2);
        assertEquals(req6.getRoleNames("sports")[0], "role1");
        assertEquals(req6.getRoleNames("sports")[1], "role2");
        assertFalse(req6.sendScopeResponse());
        assertFalse(req6.isOpenIdScope());
    }

    @Test
    public void testAccessTokenRequestOpenidDisabled() {

        AccessTokenScope.setSupportOpenIdScope(false);

        AccessTokenScope req1 = new AccessTokenScope("openid sports:service.api sports:domain");
        assertNotNull(req1);
        assertEquals(req1.getDomainName(), "sports");
        assertNull(req1.getRoleNames("sports"));
        assertTrue(req1.sendScopeResponse());
        assertFalse(req1.isOpenIdScope());
    }

    @Test
    public void testAccessTokenRequestInvalidDomains() {

        try {
            new AccessTokenScope("openid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("unknown-scope");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope(":role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("sports:role.role1 :role.role2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("sports:role.role1 openid weather:service.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("sports:role.role1 openid sports:service.api sports:service.backend");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testAccessTokenRequestNoOpenidService() {

        try {
            new AccessTokenScope("sports:domain openid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("openid :domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("sports:domain openid sports:service.");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("sports:domain openid :service.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testAccessTokenRequestMultipleDomains() {

        AccessTokenScope req1 = new AccessTokenScope("sports:domain sports:domain");
        assertNotNull(req1);

        try {
            new AccessTokenScope("sports:domain weather:domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            new AccessTokenScope("weather:role.role2 sports:domain weather:role.role1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
}

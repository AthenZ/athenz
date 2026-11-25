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

package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.zts.ZTSConsts;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.*;

public class TokenIssuanceConfigTest {

    private static final String[] PROPS = {
        ZTSConsts.ZTS_PROP_LOG_UNREQUESTED_ROLES, ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT,
        ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT,
        ZTSConsts.ZTS_PROP_JAG_TOKEN_USER_MAX_TIMEOUT, ZTSConsts.ZTS_PROP_JAG_TOKEN_SERVICE_MAX_TIMEOUT,
        ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS, ZTSConsts.ZTS_PROP_MAX_AUTHZ_DETAILS_LENGTH,
        ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH
    };

    @AfterMethod
    public void cleanup() {
        for (String prop : PROPS) {
            System.clearProperty(prop);
        }
    }

    @Test
    public void testDefaults() {
        TokenIssuanceConfig config = TokenIssuanceConfig.fromSystemProperties();
        assertEquals(config.getRoleTokenDefaultTimeout(), 7200);
        assertEquals(config.getRoleTokenMaxTimeout(), 30 * 86400);
        assertEquals(config.getIdTokenMaxTimeout(), 12 * 3600);
        assertEquals(config.getJagTokenUserMaxTimeout(), 3600);
        assertEquals(config.getJagTokenServiceMaxTimeout(), 6 * 3600);
        assertFalse(config.isLogUnrequestedRolesEnabled());
        assertNull(config.getAuthorizedProxyUsers());
        assertEquals(config.getMaxAuthzDetailsLength(), 1024);
        assertNull(config.getSystemAuthzDetails());
    }

    @Test
    public void testSystemProperties() {
        System.setProperty(ZTSConsts.ZTS_PROP_LOG_UNREQUESTED_ROLES, "true");
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, "100");
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, "200");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "300");
        System.setProperty(ZTSConsts.ZTS_PROP_JAG_TOKEN_USER_MAX_TIMEOUT, "400");
        System.setProperty(ZTSConsts.ZTS_PROP_JAG_TOKEN_SERVICE_MAX_TIMEOUT, "500");
        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS, "user.proxy1,user.proxy2");
        System.setProperty(ZTSConsts.ZTS_PROP_MAX_AUTHZ_DETAILS_LENGTH, "600");
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH,
                "src/test/resources/system_multiple_authz_details.json");

        TokenIssuanceConfig config = TokenIssuanceConfig.fromSystemProperties();
        assertTrue(config.isLogUnrequestedRolesEnabled());
        assertEquals(config.getRoleTokenDefaultTimeout(), 100);
        assertEquals(config.getRoleTokenMaxTimeout(), 200);
        assertEquals(config.getIdTokenMaxTimeout(), 300);
        assertEquals(config.getJagTokenUserMaxTimeout(), 400);
        assertEquals(config.getJagTokenServiceMaxTimeout(), 500);
        assertEquals(config.getAuthorizedProxyUsers(), Set.of("user.proxy1", "user.proxy2"));
        assertThrows(UnsupportedOperationException.class, () -> config.getAuthorizedProxyUsers().add("x"));
        assertEquals(config.getMaxAuthzDetailsLength(), 600);
        assertEquals(config.getSystemAuthzDetails().getEntities().size(), 2);
    }

    @Test
    public void testInvalidSystemAuthorizationDetails() {
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "invalid_authz_details.json");
        assertThrows(IllegalArgumentException.class, TokenIssuanceConfig::fromSystemProperties);
    }

    @Test
    public void testBuilderCopy() {
        Set<String> proxyUsers = new HashSet<>(Set.of("user.proxy"));
        TokenIssuanceConfig base = new TokenIssuanceConfig.Builder()
                .roleTokenDefaultTimeout(1).roleTokenMaxTimeout(2).idTokenMaxTimeout(3)
                .jagTokenUserMaxTimeout(4).jagTokenServiceMaxTimeout(5).logUnrequestedRolesEnabled(true)
                .authorizedProxyUsers(proxyUsers).maxAuthzDetailsLength(6)
                .systemAuthzDetails(TokenIssuanceConfig.loadSystemAuthorizationDetails())
                .build();
        proxyUsers.add("user.other");
        assertEquals(base.getAuthorizedProxyUsers(), Set.of("user.proxy"));

        TokenIssuanceConfig copy = new TokenIssuanceConfig.Builder(base).maxAuthzDetailsLength(10).build();
        assertEquals(copy.getRoleTokenDefaultTimeout(), 1);
        assertEquals(copy.getRoleTokenMaxTimeout(), 2);
        assertEquals(copy.getIdTokenMaxTimeout(), 3);
        assertEquals(copy.getJagTokenUserMaxTimeout(), 4);
        assertEquals(copy.getJagTokenServiceMaxTimeout(), 5);
        assertTrue(copy.isLogUnrequestedRolesEnabled());
        assertEquals(copy.getAuthorizedProxyUsers(), Set.of("user.proxy"));
        assertEquals(copy.getMaxAuthzDetailsLength(), 10);
        assertNull(copy.getSystemAuthzDetails());
    }
}

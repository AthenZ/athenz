/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.provider;

import static org.testng.Assert.*;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

public class ProviderMockClientTest {

    @Test
    public void testPutTenant() {
        String systemAdminUser = "user.user_admin";
        Authority authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        Principal p = SimplePrincipal.create("user", systemAdminUser,
                "v=U1;d=user;n=" + systemAdminUser + ";s=signature", 0, authority);
        ProviderMockClient provider = new ProviderMockClient("localhost:3306/athenz", p);
        Tenant tenant = new Tenant();
        tenant.setName("name");
        assertNull(provider.putTenant("providerService1", "tenantDom1", "zms", tenant));
    }

    @Test
    public void testPutTenantResourceGroup() {
        String systemAdminUser = "user.user_admin";
        Authority authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        Principal p = SimplePrincipal.create("user", systemAdminUser,
                "v=U1;d=user;n=" + systemAdminUser + ";s=signature", 0, authority);
        ProviderMockClient provider = new ProviderMockClient("localhost:3306/athenz", p);
        TenantResourceGroup tenant = new TenantResourceGroup();
        tenant.setName("name");
        assertNull(provider.putTenantResourceGroup("providerService1", "tenantDom1", "zms", "zms", tenant));
    }
}

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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.yahoo.athenz.auth.Principal;

public class ProviderMockClient extends ProviderClient {
    
    private static boolean returnTenantRoles = true;
    private static List<String> resourceGroups = new ArrayList<>();
    public ProviderMockClient(String url, Principal identity) {
        super(url);
    }
    
    static final List<String> TABLE_PROVIDER_ROLES = Arrays.asList("admin",
        "writer", "reader");
    
    static final List<String> RESOURCE_PROVIDER_ROLES = Arrays.asList("writer", "reader");
    
    @Override
    public Tenant getTenant(String providerService, String tenantDomain) {
        Tenant tenant = new Tenant();
        tenant.setName(tenantDomain).setService(providerService);
        if (!resourceGroups.isEmpty()) {
            tenant.setResourceGroups(resourceGroups);
        }
        return tenant;
    }

    @Override
    public Tenant deleteTenant(String providerService, String tenantDomain, String auditRef) {
        return null;
    }
    
    @Override
    public Tenant putTenant(String providerService, String tenantDomain, String auditRef, Tenant spec) {
        
        System.out.println("putTenant: " + tenantDomain + " -> " + spec);
        if (!tenantDomain.equals(spec.getName())) {
            return null;
        }

        if (returnTenantRoles) {
            spec.setRoles(TABLE_PROVIDER_ROLES);
        }
        return spec;
    }

    @Override
    public TenantResourceGroup deleteTenantResourceGroup(String providerService, String tenantDomain, String resourceGroup,
            String auditRef) {
        return null;
    }

    @Override
    public TenantResourceGroup putTenantResourceGroup(String providerService, String tenantDomain, String resourceGroup,
            String auditRef, TenantResourceGroup data) {
        
        System.out.println("putTenantResourceGroup: " + tenantDomain + " -> " + data);
        if (!tenantDomain.equals(data.getName())) {
            return null;
        }

        data.setRoles(RESOURCE_PROVIDER_ROLES);
        return data;
    }

    public static void setReturnTenantRoles(boolean returnTenantRoles) {
        ProviderMockClient.returnTenantRoles = returnTenantRoles;
    }
    
    public static void setResourceGroups(List<String> resourceGroups) {
        if (resourceGroups == null) {
            ProviderMockClient.resourceGroups.clear();
        } else {
            ProviderMockClient.resourceGroups.addAll(resourceGroups);
        }
    }
}

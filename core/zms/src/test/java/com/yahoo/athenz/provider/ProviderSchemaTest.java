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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

public class ProviderSchemaTest {

    @Test
    public void test() {
        Schema schema = ProviderSchema.instance();
        assertNotNull(schema);
    }

    @Test
    public void testTenants() {

        Schema schema = ProviderSchema.instance();
        Validator validator = new Validator(schema);

        Tenant t = new Tenant().setService("test-service").setName("test.domain").setState(TenantState.ACTIVE);
        Result result = validator.validate(t, "Tenant");
        assertTrue(result.valid);

        t = new Tenant().setService("test_service").setName("test.domain").setState(TenantState.ACTIVE);
        result = validator.validate(t, "Tenant");
        assertTrue(result.valid);

        t = new Tenant().setService("test@service").setName("test.domain").setState(TenantState.ACTIVE);
        result = validator.validate(t, "Tenant");
        assertFalse(result.valid);

    }

    @Test
    public void testTenantsMethods() {

        Schema schema = ProviderSchema.instance();
        Validator validator = new Validator(schema);

        List<String> roles = Arrays.asList("test-role");
        List<String> rg = Arrays.asList("test-resource-group");

        Tenant t = new Tenant().setService("test-service").setName("test.domain").setState(TenantState.ACTIVE)
                .setRoles(roles).setResourceGroups(rg);
        Result result = validator.validate(t, "Tenant");
        assertTrue(result.valid);

        assertEquals(t.getService(), "test-service");
        assertEquals(t.getName(), "test.domain");
        assertEquals(t.getState(), TenantState.ACTIVE);
        assertEquals(t.getRoles(), roles);
        assertEquals(t.getResourceGroups(), rg);
        assertEquals(t.getState(), TenantState.fromString("ACTIVE"));

        Tenant t2 = new Tenant().setService("test-service").setName("test.domain").setState(TenantState.ACTIVE)
                .setRoles(roles).setResourceGroups(rg);
        assertTrue(t.equals(t));
        
        t.setResourceGroups(null);
        assertFalse(t.equals(t2));
        t.setRoles(null);
        assertFalse(t.equals(t2));
        t.setState(null);
        assertFalse(t.equals(t2));
        t.setName(null);
        assertFalse(t.equals(t2));
        t.setService(null);
        assertFalse(t.equals(t2));
        
        assertFalse(t.equals(new String()));
    }

    @Test(expectedExceptions = { java.lang.IllegalArgumentException.class })
    public void testTenantStateException() {
        TenantState.fromString("INVALID-STATE");
    }

    @Test
    public void testTenantResourceGroup() {

        Schema schema = ProviderSchema.instance();
        Validator validator = new Validator(schema);

        TenantResourceGroup trg = new TenantResourceGroup().setService("test-service").setName("test.domain")
                .setResourceGroup("test-group");
        Result result = validator.validate(trg, "TenantResourceGroup");
        assertTrue(result.valid);

        trg = new TenantResourceGroup().setService("test@service").setName("test.domain")
                .setResourceGroup("test-group");
        result = validator.validate(trg, "TenantResourceGroup");
        assertFalse(result.valid);

    }

    @Test
    public void testTenantResourceGroupMethods() {
        Schema schema = ProviderSchema.instance();
        Validator validator = new Validator(schema);

        List<String> roles = Arrays.asList("test-role");

        TenantResourceGroup trg = new TenantResourceGroup().setService("test-service").setName("test.domain")
                .setResourceGroup("test-group").setRoles(roles);

        Result result = validator.validate(trg, "TenantResourceGroup");
        assertTrue(result.valid);

        assertEquals(trg.getService(), "test-service");
        assertEquals(trg.getName(), "test.domain");
        assertEquals(trg.getResourceGroup(), "test-group");
        assertEquals(trg.getRoles(), roles);

        TenantResourceGroup trg2 = new TenantResourceGroup().setService("test-service").setName("test.domain")
                .setResourceGroup("test-group").setRoles(roles);

        assertTrue(trg.equals(trg));
        trg.setRoles(null);
        assertFalse(trg.equals(trg2));
        trg.setResourceGroup(null);
        assertFalse(trg.equals(trg2));
        trg.setName(null);
        assertFalse(trg.equals(trg2));
        trg.setService(null);
        assertFalse(trg.equals(trg2));
        assertFalse(trg.equals(new String()));

    }
}

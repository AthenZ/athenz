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
package com.yahoo.athenz.zms.utils;

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.zms.*;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ResourceOwnershipTest {

    @Test
    public void testResourceOwnershipConstructor() {
        new ResourceOwnership();
    }

    @Test
    public void testGenerateResourceDomainOwnerString() {
        ResourceDomainOwnership resourceOwner = new ResourceDomainOwnership();
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "");

        resourceOwner.setObjectOwner("object-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner");

        resourceOwner.setMetaOwner("meta-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner,meta:meta-owner");

        resourceOwner.setObjectOwner(null);
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "meta:meta-owner");

        resourceOwner.setObjectOwner("");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "meta:meta-owner");
    }

    @Test
    public void testGenerateResourceRoleOwnerString() {
        ResourceRoleOwnership resourceOwner = new ResourceRoleOwnership();
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "");

        resourceOwner.setObjectOwner("object-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner");

        resourceOwner.setMetaOwner("meta-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner,meta:meta-owner");

        resourceOwner.setMembersOwner("members-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner,meta:meta-owner,members:members-owner");

        resourceOwner.setObjectOwner(null);
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "meta:meta-owner,members:members-owner");

        resourceOwner.setObjectOwner("");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "meta:meta-owner,members:members-owner");
    }

    @Test
    public void testGenerateResourceGroupOwnerString() {
        ResourceGroupOwnership resourceOwner = new ResourceGroupOwnership();
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "");

        resourceOwner.setObjectOwner("object-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner");

        resourceOwner.setMetaOwner("meta-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner,meta:meta-owner");

        resourceOwner.setMembersOwner("members-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner,meta:meta-owner,members:members-owner");

        resourceOwner.setObjectOwner(null);
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "meta:meta-owner,members:members-owner");

        resourceOwner.setObjectOwner("");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "meta:meta-owner,members:members-owner");
    }

    @Test
    public void testGenerateResourcePolicyOwnerString() {
        ResourcePolicyOwnership resourceOwner = new ResourcePolicyOwnership();
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "");

        resourceOwner.setObjectOwner("object-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner");

        resourceOwner.setAssertionsOwner("assertions-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner,assertions:assertions-owner");

        resourceOwner.setObjectOwner(null);
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "assertions:assertions-owner");

        resourceOwner.setObjectOwner("");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "assertions:assertions-owner");
    }

    @Test
    public void testGenerateResourceServiceOwnerString() {
        ResourceServiceIdentityOwnership resourceOwner = new ResourceServiceIdentityOwnership();
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "");

        resourceOwner.setObjectOwner("object-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "object:object-owner");

        resourceOwner.setPublicKeysOwner("publickeys-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner),
                "object:object-owner,publickeys:publickeys-owner");

        resourceOwner.setHostsOwner("hosts-owner");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner),
                "object:object-owner,publickeys:publickeys-owner,hosts:hosts-owner");

        resourceOwner.setObjectOwner(null);
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner),
                "publickeys:publickeys-owner,hosts:hosts-owner");

        resourceOwner.setObjectOwner("");
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner),
                "publickeys:publickeys-owner,hosts:hosts-owner");

        resourceOwner.setPublicKeysOwner(null);
        assertEquals(ResourceOwnership.generateResourceOwnerString(resourceOwner), "hosts:hosts-owner");
    }

    @Test
    public void testGetResourcePolicyOwnership() {
        assertNull(ResourceOwnership.getResourcePolicyOwnership(null));
        assertNull(ResourceOwnership.getResourcePolicyOwnership(""));

        ResourcePolicyOwnership resourceOwnership =
                ResourceOwnership.getResourcePolicyOwnership("object:object-owner,assertions:assertions-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getAssertionsOwner(), "assertions-owner");

        resourceOwnership = ResourceOwnership.getResourcePolicyOwnership("object:object-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getAssertionsOwner());

        resourceOwnership = ResourceOwnership.getResourcePolicyOwnership("object:object-owner,unknown:test");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getAssertionsOwner());
    }

    @Test
    public void testGetResourceRoleOwnership() {
        assertNull(ResourceOwnership.getResourceRoleOwnership(null));
        assertNull(ResourceOwnership.getResourceRoleOwnership(""));

        ResourceRoleOwnership resourceOwnership =
                ResourceOwnership.getResourceRoleOwnership("object:object-owner,meta:meta-owner,members:members-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertEquals(resourceOwnership.getMembersOwner(), "members-owner");

        resourceOwnership = ResourceOwnership.getResourceRoleOwnership("object:object-owner,meta:meta-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertNull(resourceOwnership.getMembersOwner());

        resourceOwnership = ResourceOwnership.getResourceRoleOwnership("object:object-owner,meta:meta-owner,unknown:test");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertNull(resourceOwnership.getMembersOwner());
    }

    @Test
    public void testGetResourceGroupOwnership() {
        assertNull(ResourceOwnership.getResourceGroupOwnership(null));
        assertNull(ResourceOwnership.getResourceGroupOwnership(""));

        ResourceGroupOwnership resourceOwnership =
                ResourceOwnership.getResourceGroupOwnership("object:object-owner,meta:meta-owner,members:members-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertEquals(resourceOwnership.getMembersOwner(), "members-owner");

        resourceOwnership = ResourceOwnership.getResourceGroupOwnership("object:object-owner,meta:meta-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertNull(resourceOwnership.getMembersOwner());

        resourceOwnership = ResourceOwnership.getResourceGroupOwnership("object:object-owner,meta:meta-owner,unknown:test");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertNull(resourceOwnership.getMembersOwner());
    }

    @Test
    public void testGetResourceServiceIdentityOwnership() {
        assertNull(ResourceOwnership.getResourceServiceOwnership(null));
        assertNull(ResourceOwnership.getResourceServiceOwnership(""));

        ResourceServiceIdentityOwnership resourceOwnership =
                ResourceOwnership.getResourceServiceOwnership("object:object-owner,publickeys:publickeys-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "publickeys-owner");

        resourceOwnership = ResourceOwnership.getResourceServiceOwnership("object:object-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getPublicKeysOwner());

        resourceOwnership = ResourceOwnership.getResourceServiceOwnership("object:object-owner,unknown:test");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getPublicKeysOwner());
    }

    @Test
    public void testGetResourceDomainOwnership() {
        assertNull(ResourceOwnership.getResourceDomainOwnership(null));
        assertNull(ResourceOwnership.getResourceDomainOwnership(""));

        ResourceDomainOwnership resourceOwnership =
                ResourceOwnership.getResourceDomainOwnership("object:object-owner,meta:meta-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");

        resourceOwnership = ResourceOwnership.getResourceDomainOwnership("object:object-owner");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getMetaOwner());

        resourceOwnership = ResourceOwnership.getResourceDomainOwnership("object:object-owner,unknown:test");
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getMetaOwner());
    }

    @Test
    public void testOwnershipCheckFailure() {
        assertTrue(ResourceOwnership.ownershipCheckFailure(true, "TF", null));
        assertTrue(ResourceOwnership.ownershipCheckFailure(true, "TF", ""));
        assertTrue(ResourceOwnership.ownershipCheckFailure(true, "TF", "MSD"));
        assertFalse(ResourceOwnership.ownershipCheckFailure(true, "TF", "TF"));

        assertTrue(ResourceOwnership.ownershipCheckFailure(false, null, "TF"));
        assertFalse(ResourceOwnership.ownershipCheckFailure(false, null, ""));
        assertFalse(ResourceOwnership.ownershipCheckFailure(false, null, null));
    }

    @Test
    public void testVerifyDeleteResourceObjectOwnership() {

        // for all objects verify that if the object doesn't have
        // resource ownership or no object owner then we return right
        // away without any checks

        ResourceOwnership.verifyRoleDeleteResourceOwnership(new Role(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyRoleDeleteResourceOwnership(new Role()
                        .setResourceOwnership(new ResourceRoleOwnership()), "resourceOwner", "unit-test");

        ResourceOwnership.verifyPolicyDeleteResourceOwnership(new Policy(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyPolicyDeleteResourceOwnership(new Policy()
                        .setResourceOwnership(new ResourcePolicyOwnership()), "resourceOwner", "unit-test");

        ResourceOwnership.verifyGroupDeleteResourceOwnership(new Group(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyGroupDeleteResourceOwnership(new Group()
                        .setResourceOwnership(new ResourceGroupOwnership()), "resourceOwner", "unit-test");

        ResourceOwnership.verifyServiceDeleteResourceOwnership(new ServiceIdentity(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyServiceDeleteResourceOwnership(new ServiceIdentity()
                        .setResourceOwnership(new ResourceServiceIdentityOwnership()), "resourceOwner", "unit-test");
    }

    @Test
    public void testSkipEnforceResourceOwnership() {
        // by default, we should enforce resource ownership
        assertFalse(ResourceOwnership.skipEnforceResourceOwnership("TF"));
        // with our special value we should skip the enforcement
        assertTrue(ResourceOwnership.skipEnforceResourceOwnership("ignore"));
        // with feature disabled we should skip the enforcement
        DynamicConfigBoolean configBoolean = new DynamicConfigBoolean(false);
        DynamicConfigBoolean saveConfig = ResourceOwnership.ENFORCE_RESOURCE_OWNERSHIP;
        ResourceOwnership.ENFORCE_RESOURCE_OWNERSHIP = configBoolean;
        assertTrue(ResourceOwnership.skipEnforceResourceOwnership("TF"));
        assertTrue(ResourceOwnership.skipEnforceResourceOwnership("ignore"));
        ResourceOwnership.ENFORCE_RESOURCE_OWNERSHIP = saveConfig;
    }

      @Test
    public void testVerifyRoleMembersDeleteResourceOwnership() {

        ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(new Role(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(new Role()
                .setResourceOwnership(new ResourceRoleOwnership()), "resourceOwner", "unit-test");

        Role memberOwnerRole = new Role().setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("role-member"));
        try {
            ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(memberOwnerRole, "resourceOwner", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 409);
        }

        Role objectOwnerRole = new Role().setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("object-owner"));
        try {
            ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(objectOwnerRole, "resourceOwner", "unit-test");
        } catch (ResourceException ex) {
            fail();
        }
    }

    @Test
    public void testVerifyGroupMembersDeleteResourceOwnership() {

        ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(new Group(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(new Group()
                .setResourceOwnership(new ResourceGroupOwnership()), "resourceOwner", "unit-test");

        Group memberOwnerGroup = new Group().setResourceOwnership(new ResourceGroupOwnership().setMembersOwner("role-member"));
        try {
            ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(memberOwnerGroup, "resourceOwner", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 409);
        }

        Group objectOwnerGroup = new Group().setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("object-owner"));
        try {
            ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(objectOwnerGroup, "resourceOwner", "unit-test");
        } catch (ResourceException ex) {
            fail();
        }
    }
  
    @Test
    public void testVerifyPolicyAssertionsDeleteResourceOwnership() {

        ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(new Policy(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(new Policy()
                .setResourceOwnership(new ResourcePolicyOwnership()), "resourceOwner", "unit-test");

        Policy assertionsOwnerPolicy = new Policy().setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("assertions-owner"));
        try {
            ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(assertionsOwnerPolicy, "resourceOwner", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 409);
        }

        Policy objectOwnerPolicy = new Policy().setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("object-owner"));
        try {
            ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(objectOwnerPolicy, "resourceOwner", "unit-test");
        } catch (ResourceException ex) {
            fail();
        }
    }
}

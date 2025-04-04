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
package com.yahoo.athenz.common.server.util;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.zms.*;
import org.testng.Assert;
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
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getAssertionsOwner(), "assertions-owner");

        resourceOwnership = ResourceOwnership.getResourcePolicyOwnership("object:object-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getAssertionsOwner());

        resourceOwnership = ResourceOwnership.getResourcePolicyOwnership("object:object-owner,unknown:test");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getAssertionsOwner());
    }

    @Test
    public void testGetResourceRoleOwnership() {
        assertNull(ResourceOwnership.getResourceRoleOwnership(null));
        assertNull(ResourceOwnership.getResourceRoleOwnership(""));

        ResourceRoleOwnership resourceOwnership =
                ResourceOwnership.getResourceRoleOwnership("object:object-owner,meta:meta-owner,members:members-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertEquals(resourceOwnership.getMembersOwner(), "members-owner");

        resourceOwnership = ResourceOwnership.getResourceRoleOwnership("object:object-owner,meta:meta-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertNull(resourceOwnership.getMembersOwner());

        resourceOwnership = ResourceOwnership.getResourceRoleOwnership("object:object-owner,meta:meta-owner,unknown:test");
        assertNotNull(resourceOwnership);
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
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertEquals(resourceOwnership.getMembersOwner(), "members-owner");

        resourceOwnership = ResourceOwnership.getResourceGroupOwnership("object:object-owner,meta:meta-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");
        assertNull(resourceOwnership.getMembersOwner());

        resourceOwnership = ResourceOwnership.getResourceGroupOwnership("object:object-owner,meta:meta-owner,unknown:test");
        assertNotNull(resourceOwnership);
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
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "publickeys-owner");

        resourceOwnership = ResourceOwnership.getResourceServiceOwnership("object:object-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getPublicKeysOwner());

        resourceOwnership = ResourceOwnership.getResourceServiceOwnership("object:object-owner,unknown:test");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getPublicKeysOwner());
    }

    @Test
    public void testGetResourceDomainOwnership() {
        assertNull(ResourceOwnership.getResourceDomainOwnership(null));
        assertNull(ResourceOwnership.getResourceDomainOwnership(""));

        ResourceDomainOwnership resourceOwnership =
                ResourceOwnership.getResourceDomainOwnership("object:object-owner,meta:meta-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertEquals(resourceOwnership.getMetaOwner(), "meta-owner");

        resourceOwnership = ResourceOwnership.getResourceDomainOwnership("object:object-owner");
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "object-owner");
        assertNull(resourceOwnership.getMetaOwner());

        resourceOwnership = ResourceOwnership.getResourceDomainOwnership("object:object-owner,unknown:test");
        assertNotNull(resourceOwnership);
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
    public void testVerifyDeleteResourceObjectOwnership() throws ServerResourceException {

        // for all objects verify that if the object doesn't have
        // resource ownership or no object owner then we return right
        // away without any checks

        ResourceOwnership.verifyRoleDeleteResourceOwnership(new Role(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyRoleDeleteResourceOwnership(new Role()
                        .setResourceOwnership(new ResourceRoleOwnership()), "resourceOwner", "unit-test");
        ResourceOwnership.verifyRoleDeleteResourceOwnership(new Role()
                .setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("A")), "A:force", "unit-test");
        try {
            ResourceOwnership.verifyRoleDeleteResourceOwnership(new Role()
                    .setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("A")), "B:force", "unit-test");
            fail();
        }catch (ServerResourceException ignored) {

        }

        ResourceOwnership.verifyPolicyDeleteResourceOwnership(new Policy(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyPolicyDeleteResourceOwnership(new Policy()
                        .setResourceOwnership(new ResourcePolicyOwnership()), "resourceOwner", "unit-test");
        ResourceOwnership.verifyPolicyDeleteResourceOwnership(new Policy()
                .setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("A")), "A:force", "unit-test");
        try {
            ResourceOwnership.verifyPolicyDeleteResourceOwnership(new Policy()
                    .setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("A")), "B:force", "unit-test");
            fail();
        } catch (ServerResourceException ignored) {
        }


        ResourceOwnership.verifyGroupDeleteResourceOwnership(new Group(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyGroupDeleteResourceOwnership(new Group()
                        .setResourceOwnership(new ResourceGroupOwnership()), "resourceOwner", "unit-test");
        ResourceOwnership.verifyGroupDeleteResourceOwnership(new Group()
                .setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("A")), "A:force", "unit-test");
        try {
            ResourceOwnership.verifyGroupDeleteResourceOwnership(new Group()
                    .setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("A")), "B:force", "unit-test");
            fail();
        } catch (ServerResourceException ignored) {
        }

        ResourceOwnership.verifyServiceDeleteResourceOwnership(new ServiceIdentity(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyServiceDeleteResourceOwnership(new ServiceIdentity()
                        .setResourceOwnership(new ResourceServiceIdentityOwnership()), "resourceOwner", "unit-test");
        ResourceOwnership.verifyServiceDeleteResourceOwnership(new ServiceIdentity()
                .setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("A")), "A:force", "unit-test");
        try {
            ResourceOwnership.verifyServiceDeleteResourceOwnership(new ServiceIdentity()
                    .setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("A")), "B:force", "unit-test");
            fail();
        } catch (ServerResourceException ignored) {
        }
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
    public void testVerifyRoleMembersDeleteResourceOwnership() throws ServerResourceException {

        ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(new Role(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(new Role()
                .setResourceOwnership(new ResourceRoleOwnership()), "resourceOwner", "unit-test");

        Role memberOwnerRole = new Role().setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("role-member"));
        try {
            ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(memberOwnerRole, "resourceOwner", "unit-test");
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), 409);
        }

        Role objectOwnerRole = new Role().setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("object-owner"));
        try {
            ResourceOwnership.verifyRoleMembersDeleteResourceOwnership(objectOwnerRole, "resourceOwner", "unit-test");
        } catch (ServerResourceException ex) {
            fail();
        }
    }

    @Test
    public void testVerifyGroupMembersDeleteResourceOwnership() throws ServerResourceException {

        ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(new Group(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(new Group()
                .setResourceOwnership(new ResourceGroupOwnership()), "resourceOwner", "unit-test");

        Group memberOwnerGroup = new Group().setResourceOwnership(new ResourceGroupOwnership().setMembersOwner("role-member"));
        try {
            ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(memberOwnerGroup, "resourceOwner", "unit-test");
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), 409);
        }

        Group objectOwnerGroup = new Group().setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("object-owner"));
        try {
            ResourceOwnership.verifyGroupMembersDeleteResourceOwnership(objectOwnerGroup, "resourceOwner", "unit-test");
        } catch (ServerResourceException ex) {
            fail();
        }
    }

    @Test
    public void testVerifyPolicyAssertionsDeleteResourceOwnership() throws ServerResourceException {

        ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(new Policy(), "resourceOwner", "unit-test");
        ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(new Policy()
                .setResourceOwnership(new ResourcePolicyOwnership()), "resourceOwner", "unit-test");

        Policy assertionsOwnerPolicy = new Policy().setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("assertions-owner"));
        try {
            ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(assertionsOwnerPolicy, "resourceOwner", "unit-test");
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), 409);
        }

        Policy objectOwnerPolicy = new Policy().setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("object-owner"));
        try {
            ResourceOwnership.verifyPolicyAssertionsDeleteResourceOwnership(objectOwnerPolicy, "resourceOwner", "unit-test");
        } catch (ServerResourceException ex) {
            fail();
        }
    }

    @Test
    public void testIsResourceOwnershipOverrideAllowed() {
        assertFalse(ResourceOwnership.isResourceOwnershipOverrideAllowed(null, "TF2"));
        assertFalse(ResourceOwnership.isResourceOwnershipOverrideAllowed("TF1", "TF2"));
        assertFalse(ResourceOwnership.isResourceOwnershipOverrideAllowed("TF1:abc", "TF2"));
        assertFalse(ResourceOwnership.isResourceOwnershipOverrideAllowed("TF2:force", "TF2"));
        assertTrue(ResourceOwnership.isResourceOwnershipOverrideAllowed("TF1:force", "TF2"));
    }

    @Test
    public void testVerifyServicePublicKeysResourceOwnership() {
        ResourceServiceIdentityOwnership ownership;
        // no changes needed when resource ownership is same
        ServiceIdentity service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setPublicKeysOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setPublicKeysOwner(""));
        try {
            ownership = ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        service = new ServiceIdentity().setName("service1");
        try {
            ownership = ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        service = new ServiceIdentity().setName("service1");
        try {
            ownership = ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getPublicKeysOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setPublicKeysOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getPublicKeysOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setPublicKeysOwner("TF1"));
        try {
            ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setPublicKeysOwner("TF1"));
        try {
            ResourceOwnership.verifyServicePublicKeysResourceOwnership(service, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyServiceResourceOwnership() {
        ResourceServiceIdentityOwnership ownership;
        // no changes needed when resource ownership is same
        ServiceIdentity service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF1").setPublicKeysOwner("TF1").setHostsOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyServiceResourceOwnership(service, true, true,"TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner(""));
        try {
            ownership = ResourceOwnership.verifyServiceResourceOwnership(service, false, false,null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        service = new ServiceIdentity().setName("service1");
        try {
            ownership = ResourceOwnership.verifyServiceResourceOwnership(service, false, false,"ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        service = new ServiceIdentity().setName("service1");
        try {
            ownership = ResourceOwnership.verifyServiceResourceOwnership(service, false, false,"TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyServiceResourceOwnership(service, false, false,"TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyServiceResourceOwnership(service, false, false,"TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        service = new ServiceIdentity().setName("service1").setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyServiceResourceOwnership(service, false, false,null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyPolicyAssertionsResourceOwnership() {
        ResourcePolicyOwnership ownership;
        // no changes needed when resource ownership is same
        Policy policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner(""));
        try {
            ownership = ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        policy = new Policy().setName("policy1");
        try {
            ownership = ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        policy = new Policy().setName("policy1");
        try {
            ownership = ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getAssertionsOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getAssertionsOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("TF1"));
        try {
            ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("TF1"));
        try {
            ResourceOwnership.verifyPolicyAssertionsResourceOwnership(policy, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyPolicyResourceOwnership() {
        ResourcePolicyOwnership ownership;
        // no changes needed when resource ownership is same
        Policy policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF1").setAssertionsOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyPolicyResourceOwnership(policy, true, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner(""));
        try {
            ownership = ResourceOwnership.verifyPolicyResourceOwnership(policy, true, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        policy = new Policy().setName("policy1");
        try {
            ownership = ResourceOwnership.verifyPolicyResourceOwnership(policy, true, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        policy = new Policy().setName("policy1");
        try {
            ownership = ResourceOwnership.verifyPolicyResourceOwnership(policy, true, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getAssertionsOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyPolicyResourceOwnership(policy, true, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getAssertionsOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no-op needed when resource ownership is same and force overridden
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF2"));
        try {
            ownership = ResourceOwnership.verifyPolicyResourceOwnership(policy, true, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getAssertionsOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyPolicyResourceOwnership(policy, true, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        policy = new Policy().setName("policy1").setResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyPolicyResourceOwnership(policy, true, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyGroupMembersResourceOwnership() {
        ResourceGroupOwnership ownership;
        // no changes needed when resource ownership is same
        Group group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMembersOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyGroupMembersResourceOwnership(group, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMembersOwner(""));
        try {
            ownership = ResourceOwnership.verifyGroupMembersResourceOwnership(group, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        group = new Group().setName("group1");
        try {
            ownership = ResourceOwnership.verifyGroupMembersResourceOwnership(group, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        group = new Group().setName("group1");
        try {
            ownership = ResourceOwnership.verifyGroupMembersResourceOwnership(group, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMembersOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMembersOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyGroupMembersResourceOwnership(group, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMembersOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMembersOwner("TF1"));
        try {
            ResourceOwnership.verifyGroupMembersResourceOwnership(group, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMembersOwner("TF1"));
        try {
            ResourceOwnership.verifyGroupMembersResourceOwnership(group, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyGroupMetaResourceOwnership() {
        ResourceGroupOwnership ownership;
        // no changes needed when resource ownership is same
        Group group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyGroupMetaResourceOwnership(group, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner(""));
        try {
            ownership = ResourceOwnership.verifyGroupMetaResourceOwnership(group, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        group = new Group().setName("group1");
        try {
            ownership = ResourceOwnership.verifyGroupMetaResourceOwnership(group, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        group = new Group().setName("group1");
        try {
            ownership = ResourceOwnership.verifyGroupMetaResourceOwnership(group, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMetaOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyGroupMetaResourceOwnership(group, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMetaOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no-op when resource ownership is same and force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF2"));
        try {
            ownership = ResourceOwnership.verifyGroupMetaResourceOwnership(group, "TF2:force", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF1"));
        try {
            ResourceOwnership.verifyGroupMetaResourceOwnership(group, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF1"));
        try {
            ResourceOwnership.verifyGroupMetaResourceOwnership(group, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyGroupResourceOwnership() {
        ResourceGroupOwnership ownership;
        // no changes needed when resource ownership is same
        Group group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF1").setMembersOwner("TF1").setMetaOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyGroupResourceOwnership(group, true, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setMetaOwner(""));
        try {
            ownership = ResourceOwnership.verifyGroupResourceOwnership(group, true, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        group = new Group().setName("group1");
        try {
            ownership = ResourceOwnership.verifyGroupResourceOwnership(group, true, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        group = new Group().setName("group1");
        try {
            ownership = ResourceOwnership.verifyGroupResourceOwnership(group, true, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyGroupResourceOwnership(group, true, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no-op when resource ownership is force overridden with the same value
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF2"));
        try {
            ownership = ResourceOwnership.verifyGroupResourceOwnership(group, true, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyGroupResourceOwnership(group, true, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        group = new Group().setName("group1").setResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyGroupResourceOwnership(group, true, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyRoleResourceOwnership() {
        ResourceRoleOwnership ownership;
        // no changes needed when resource ownership is same
        Role role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF1").setMembersOwner("TF1").setMetaOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyRoleResourceOwnership(role, true, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setObjectOwner(""));
        try {
            ownership = ResourceOwnership.verifyRoleResourceOwnership(role, true, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        role = new Role().setName("role1");
        try {
            ownership = ResourceOwnership.verifyRoleResourceOwnership(role, true, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        role = new Role().setName("role1");
        try {
            ownership = ResourceOwnership.verifyRoleResourceOwnership(role, true, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyRoleResourceOwnership(role, true, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no-op when resource ownership is force overridden with the same value
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF2"));
        try {
            ownership = ResourceOwnership.verifyRoleResourceOwnership(role, true, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getObjectOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleResourceOwnership(role, true, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleResourceOwnership(role, true, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyRoleMemberResourceOwnership() {
        ResourceRoleOwnership ownership;
        // no changes needed when resource ownership is same
        Role role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyRoleMembersResourceOwnership(role, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMembersOwner(""));
        try {
            ownership = ResourceOwnership.verifyRoleMembersResourceOwnership(role, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        role = new Role().setName("role1");
        try {
            ownership = ResourceOwnership.verifyRoleMembersResourceOwnership(role, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        role = new Role().setName("role1");
        try {
            ownership = ResourceOwnership.verifyRoleMembersResourceOwnership(role, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMembersOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyRoleMembersResourceOwnership(role, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMembersOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no-op when second time called with same owner
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("TF2"));
        try {
            ownership = ResourceOwnership.verifyRoleMembersResourceOwnership(role, "TF2:force", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleMembersResourceOwnership(role, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMembersOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleMembersResourceOwnership(role, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }

    @Test
    public void testVerifyRoleMetaResourceOwnership() {
        ResourceRoleOwnership ownership;
        // no changes needed when resource ownership is same
        Role role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyRoleMetaResourceOwnership(role, "TF1", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no changes needed when resource ownership is not set and no owner specified
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMetaOwner(""));
        try {
            ownership = ResourceOwnership.verifyRoleMetaResourceOwnership(role, null, "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // no changes needed when resource ownership is set and request owner is set to ignore
        role = new Role().setName("role1");
        try {
            ownership = ResourceOwnership.verifyRoleMetaResourceOwnership(role, "ignore", "unit-test");
            assertNull(ownership);
        } catch (ServerResourceException sre) {
            fail();
        }

        // changes needed when resource ownership is not set and request owner is specified
        role = new Role().setName("role1");
        try {
            ownership = ResourceOwnership.verifyRoleMetaResourceOwnership(role, "TF1", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMetaOwner(), "TF1");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // changes needed when resource ownership is force overridden
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF1"));
        try {
            ownership = ResourceOwnership.verifyRoleMetaResourceOwnership(role, "TF2:force", "unit-test");
            assertNotNull(ownership);
            assertEquals(ownership.getMetaOwner(), "TF2");
        } catch (ServerResourceException ignored) {
            fail();
        }

        // no-op when second time called with same owner
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleMetaResourceOwnership(role, "TF2:force", "unit-test");
        } catch (ServerResourceException sre) {
            fail();
        }

        // exception is thrown when resource ownership is different and not force overridden
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleMetaResourceOwnership(role, "TF2", "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }

        // exception is thrown when resource ownership is set and no owner specified
        role = new Role().setName("role1").setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF1"));
        try {
            ResourceOwnership.verifyRoleMetaResourceOwnership(role, null, "unit-test");
            fail();
        } catch (ServerResourceException sre) {
            assertEquals(sre.getCode(), 409);
        }
    }
}

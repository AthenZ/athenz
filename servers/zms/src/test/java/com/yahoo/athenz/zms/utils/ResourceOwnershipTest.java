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
    }
}

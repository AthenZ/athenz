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

package com.yahoo.athenz.zms;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class ResourceOwnershipTest {

    @Test
    public void testResourceDomainOwnership() {

        ResourceDomainOwnership resourceOwnership1 = new ResourceDomainOwnership();
        resourceOwnership1.setMetaOwner("TF");
        resourceOwnership1.setObjectOwner("ZTS");

        ResourceDomainOwnership resourceOwnership2 = new ResourceDomainOwnership();
        resourceOwnership2.setMetaOwner("TF");
        resourceOwnership2.setObjectOwner("ZTS");

        assertEquals(resourceOwnership1, resourceOwnership1);
        assertEquals(resourceOwnership1, resourceOwnership2);

        // verify getters
        assertEquals("TF", resourceOwnership1.getMetaOwner());
        assertEquals("ZTS", resourceOwnership1.getObjectOwner());

        resourceOwnership1.setMetaOwner("TF2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMetaOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMetaOwner("TF");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setObjectOwner("ZTS2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner("ZTS");
        assertEquals(resourceOwnership1, resourceOwnership2);

        assertNotEquals(resourceOwnership1, null);
        assertNotEquals("data", resourceOwnership2);
    }

    @Test
    public void testResourceRoleOwnership() {

        ResourceRoleOwnership resourceOwnership1 = new ResourceRoleOwnership();
        resourceOwnership1.setMetaOwner("TF");
        resourceOwnership1.setObjectOwner("ZTS");
        resourceOwnership1.setMembersOwner("UI");

        ResourceRoleOwnership resourceOwnership2 = new ResourceRoleOwnership();
        resourceOwnership2.setMetaOwner("TF");
        resourceOwnership2.setObjectOwner("ZTS");
        resourceOwnership2.setMembersOwner("UI");

        assertEquals(resourceOwnership1, resourceOwnership1);
        assertEquals(resourceOwnership1, resourceOwnership2);

        // verify getters
        assertEquals("TF", resourceOwnership1.getMetaOwner());
        assertEquals("ZTS", resourceOwnership1.getObjectOwner());
        assertEquals("UI", resourceOwnership1.getMembersOwner());

        resourceOwnership1.setMetaOwner("TF2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMetaOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMetaOwner("TF");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setObjectOwner("ZTS2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner("ZTS");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setMembersOwner("UI2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMembersOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMembersOwner("UI");
        assertEquals(resourceOwnership1, resourceOwnership2);

        assertNotEquals(resourceOwnership1, null);
        assertNotEquals("data", resourceOwnership2);
    }

    @Test
    public void testResourceGroupOwnership() {

        ResourceGroupOwnership resourceOwnership1 = new ResourceGroupOwnership();
        resourceOwnership1.setMetaOwner("TF");
        resourceOwnership1.setObjectOwner("ZTS");
        resourceOwnership1.setMembersOwner("UI");

        ResourceGroupOwnership resourceOwnership2 = new ResourceGroupOwnership();
        resourceOwnership2.setMetaOwner("TF");
        resourceOwnership2.setObjectOwner("ZTS");
        resourceOwnership2.setMembersOwner("UI");

        assertEquals(resourceOwnership1, resourceOwnership1);
        assertEquals(resourceOwnership1, resourceOwnership2);

        // verify getters
        assertEquals("TF", resourceOwnership1.getMetaOwner());
        assertEquals("ZTS", resourceOwnership1.getObjectOwner());
        assertEquals("UI", resourceOwnership1.getMembersOwner());

        resourceOwnership1.setMetaOwner("TF2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMetaOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMetaOwner("TF");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setObjectOwner("ZTS2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner("ZTS");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setMembersOwner("UI2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMembersOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setMembersOwner("UI");
        assertEquals(resourceOwnership1, resourceOwnership2);

        assertNotEquals(resourceOwnership1, null);
        assertNotEquals("data", resourceOwnership2);
    }

    @Test
    public void testResourcePolicyOwnership() {

        ResourcePolicyOwnership resourceOwnership1 = new ResourcePolicyOwnership();
        resourceOwnership1.setAssertionsOwner("TF");
        resourceOwnership1.setObjectOwner("ZTS");

        ResourcePolicyOwnership resourceOwnership2 = new ResourcePolicyOwnership();
        resourceOwnership2.setAssertionsOwner("TF");
        resourceOwnership2.setObjectOwner("ZTS");

        assertEquals(resourceOwnership1, resourceOwnership1);
        assertEquals(resourceOwnership1, resourceOwnership2);

        // verify getters
        assertEquals("TF", resourceOwnership1.getAssertionsOwner());
        assertEquals("ZTS", resourceOwnership1.getObjectOwner());

        resourceOwnership1.setAssertionsOwner("TF2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setAssertionsOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setAssertionsOwner("TF");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setObjectOwner("ZTS2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner("ZTS");
        assertEquals(resourceOwnership1, resourceOwnership2);

        assertNotEquals(resourceOwnership1, null);
        assertNotEquals("data", resourceOwnership2);
    }

    @Test
    public void testResourceServiceIdentityOwnership() {

        ResourceServiceIdentityOwnership resourceOwnership1 = new ResourceServiceIdentityOwnership();
        resourceOwnership1.setPublicKeysOwner("TF");
        resourceOwnership1.setObjectOwner("ZTS");
        resourceOwnership1.setHostsOwner("MSD");

        ResourceServiceIdentityOwnership resourceOwnership2 = new ResourceServiceIdentityOwnership();
        resourceOwnership2.setPublicKeysOwner("TF");
        resourceOwnership2.setObjectOwner("ZTS");
        resourceOwnership2.setHostsOwner("MSD");

        assertEquals(resourceOwnership1, resourceOwnership1);
        assertEquals(resourceOwnership1, resourceOwnership2);

        // verify getters
        assertEquals("TF", resourceOwnership1.getPublicKeysOwner());
        assertEquals("ZTS", resourceOwnership1.getObjectOwner());
        assertEquals("MSD", resourceOwnership1.getHostsOwner());

        resourceOwnership1.setPublicKeysOwner("TF2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setPublicKeysOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setPublicKeysOwner("TF");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setObjectOwner("ZTS2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setObjectOwner("ZTS");
        assertEquals(resourceOwnership1, resourceOwnership2);

        resourceOwnership1.setHostsOwner("MSD2");
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setHostsOwner(null);
        assertNotEquals(resourceOwnership1, resourceOwnership2);
        resourceOwnership1.setHostsOwner("MSD");
        assertEquals(resourceOwnership1, resourceOwnership2);

        assertNotEquals(resourceOwnership1, null);
        assertNotEquals("data", resourceOwnership2);
    }
}

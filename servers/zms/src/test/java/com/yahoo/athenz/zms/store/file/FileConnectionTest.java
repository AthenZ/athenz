/*
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
package com.yahoo.athenz.zms.store.file;

import static org.testng.Assert.*;
import java.io.File;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.Entity;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;

public class FileConnectionTest {

    @Test
    public void testGetDomainModTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            fileconnection.getDomainModTimestamp("DummyDomain1");
        }
    }

    @Test
    public void testUpdateDomain() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                Domain domMock = Mockito.mock(Domain.class);
                Mockito.when(domMock.getName()).thenReturn("domain1");
                Mockito.when(fileconnection.getDomainStruct("domain1")).thenReturn(null);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testRemovePublicKeyEntry() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertFalse(fileconnection.removePublicKeyEntry(null, "12"));
        }
    }

    @Test
    public void testLookupDomainByRole() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.lookupDomainByRole("member1", "role1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testValidatePrincipalDomain() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.validatePrincipalDomain("principal");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdateDomainModTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.updateDomainModTimestamp("DummyDomain1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testInsertDomainTemplate() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.insertDomainTemplate("DummyDomain1", "Template1", "param");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeleteDomainTemplate() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteDomainTemplate("DummyDomain1", "Template1", "param");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testListEntities() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listEntities("DummyDomain1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testListRoleMembers() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listRoleMembers("DummyDomain1", "Role1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testInsertRoleMember() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.insertRoleMember("DummyDomain1", "Role1",
                        new RoleMember().setMemberName("principal1"), "audit1", "zmsjcltest");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdatePolicy() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            Policy policy = new Policy();
            try {
                fileconnection.updatePolicy("Domain1", policy);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeletePolicy() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deletePolicy("Domain1", "policy1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testInsertAssertion() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            Assertion assertion = new Assertion();
            try {
                fileconnection.insertAssertion("Domain1", "policy1", assertion);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testListAssertions() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listAssertions("Domain1", "Policy1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdateServiceIdentity() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            ServiceIdentity service1 = new ServiceIdentity();
            try {
                fileconnection.updateServiceIdentity("Domain1", service1);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeleteServiceIdentity() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteServiceIdentity("Domain1", "service1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testListPublicKeys() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listPublicKeys("Domain1", "service1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testListServiceHosts() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listPublicKeys("Domain1", "service1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testInsertServiceHost() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.insertServiceHost("Domain1", "service1", "athenz.zms.client.zms_url");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeleteServiceHost() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteServiceHost("Domain1", "service1", "athenz.zms.client.zms_url");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdateEntity() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            Entity entity1 = new Entity();
            try {
                fileconnection.updateEntity("Domain1", entity1);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeleteEntity() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteEntity("Domain1", "entity1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDelete() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            fileconnection.delete("zms");
        }
    }

    @Test
    public void testListResourceAccess() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listResourceAccess("principal1", "UPDATE", "UserDomain1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdatePolicyModTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.updatePolicyModTimestamp("domain1", "policy1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdateRole() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            Role role = new Role();
            try {
                fileconnection.updateRole("domain1", role);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdateRoleModTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.updateRoleModTimestamp("domain1", "role1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeleteRole() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteRole("domain1", "role1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testListServiceHostsList() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listServiceHosts("domain1", "service1");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testGetRoleObject() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            DomainStruct domain = new DomainStruct();
            fileconnection.getRoleObject(domain, "role1");
        }
    }

    @Test
    public void testGetPolicyObject() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            DomainStruct domain = new DomainStruct();
            fileconnection.getPolicyObject(domain, "role1");
        }
    }

    @Test
    public void testDeleteRoleMember() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteRoleMember("domain1", "role1", "principal", "admin", "zmsjcltest");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testGetAssertion() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            long assertid = 33456;
            try {
                fileconnection.getAssertion("domain1", "policy1", assertid);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeleteAssertion() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            long assertid = 33456;
            try {
                fileconnection.deleteAssertion("domain1", "policy1", assertid);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testDeletePublicKeyEntry() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deletePublicKeyEntry("domain1", "service1", "223");
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testUpdatePublicKeyEntry() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            try {
                fileconnection.updatePublicKeyEntry("domain1", "service1", keyEntry);
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testAssertionMatch() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        Assertion assertion1 = new Assertion();
        assertion1.setAction("UPDATE").setResource("resource").setRole("zmsRole");
        Assertion assertion2 = new Assertion();
        assertion2.setAction("UPDATE").setResource("resource").setRole("zmsRole");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertTrue(fileconnection.assertionMatch(assertion1, assertion2));

            Assertion assertion3 = new Assertion();
            assertion3.setAction("UPDATE").setResource("resource").setRole("zmsRole");
            Assertion assertion4 = new Assertion();
            assertion4.setAction("Delete").setResource("resource").setRole("zmsRole");
            assertFalse(fileconnection.assertionMatch(assertion3, assertion4));

            Assertion assertion5 = new Assertion();
            assertion5.setAction("UPDATE").setResource("resource1").setRole("zmsRole");
            Assertion assertion6 = new Assertion();
            assertion6.setAction("UPDATE").setResource("resource2").setRole("zmsRole");
            assertFalse(fileconnection.assertionMatch(assertion5, assertion6));

            Assertion assertion7 = new Assertion();
            assertion7.setAction("UPDATE").setResource("resource").setRole("zmsRole1");
            Assertion assertion8 = new Assertion();
            assertion8.setAction("UPDATE").setResource("resource").setRole("zmsRole2");
            assertFalse(fileconnection.assertionMatch(assertion7, assertion8));

            Assertion assertion9 = new Assertion();
            AssertionEffect effect1 = AssertionEffect.ALLOW;
            assertion9.setAction("UPDATE").setResource("resource").setRole("zmsRole").setEffect(effect1);
            Assertion assertion10 = new Assertion();
            assertion10.setAction("UPDATE").setResource("resource").setRole("zmsRole").setEffect(effect1);
            assertTrue(fileconnection.assertionMatch(assertion9, assertion10));

            Assertion assertion11 = new Assertion();
            AssertionEffect effect2 = AssertionEffect.ALLOW;
            AssertionEffect effect3 = AssertionEffect.DENY;
            assertion11.setAction("UPDATE").setResource("resource").setRole("zmsRole").setEffect(effect2);
            Assertion assertion12 = new Assertion();
            assertion12.setAction("UPDATE").setResource("resource").setRole("zmsRole").setEffect(effect3);
            assertFalse(fileconnection.assertionMatch(assertion11, assertion12));
        }
    }
}

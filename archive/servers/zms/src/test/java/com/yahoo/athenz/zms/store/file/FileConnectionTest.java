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
package com.yahoo.athenz.zms.store.file;

import static org.testng.Assert.*;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class FileConnectionTest {

    @Test
    public void testGetDomainModTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertEquals(fileconnection.getDomainModTimestamp("DummyDomain1"), 0);
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
                fail();
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
            assertTrue(fileconnection.lookupDomainByRole("member1", "role1").isEmpty());
        }
    }

    @Test
    public void testValidatePrincipalDomain() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertFalse(fileconnection.validatePrincipalDomain("principal"));
        }
    }

    @Test
    public void testUpdateDomainModTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.updateDomainModTimestamp("DummyDomain1");
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fileconnection.listRoleMembers("DummyDomain1", "Role1", false);
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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
            assertFalse(fileconnection.delete("zms"));
        }
    }

    @Test
    public void testListResourceAccess() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.listResourceAccess("principal1", "UPDATE", "UserDomain1");
                fail();
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
                fail();
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
            role.setAuditEnabled(false);
            try {
                fileconnection.updateRole("domain1", role);
                fail();
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
                fail();
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
                fail();
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
                fail();
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
            assertNull(fileconnection.getRoleObject(domain, "role1"));
        }
    }

    @Test
    public void testGetPolicyObject() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            DomainStruct domain = new DomainStruct();
            assertNull(fileconnection.getPolicyObject(domain, "role1"));
        }
    }

    @Test
    public void testDeleteRoleMember() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deleteRoleMember("domain1", "role1", "principal", "admin", "zmsjcltest");
                fail();
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
                fail();
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
                fail();
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
                fail();
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
                fail();
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

    @Test
    public void testConfirmRoleMember() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.confirmRoleMember("DummyDomain1", "Role1",
                        new RoleMember().setMemberName("principal1"), "audit1", "zmsjcltest");
                fail();
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testGetPendingDomainRoleMembersList() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertTrue(fileconnection.getPendingDomainRoleMembers("user.user1").isEmpty());
        }
    }

    @Test
    public void testGetRoleObjectWithPending() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            DomainStruct domain = new DomainStruct();
            assertNull(fileconnection.getRoleObject(domain, "role1", false));
        }
    }

    @Test
    public void testgetPendingMembershipApproverRoles() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertTrue(fileconnection.getPendingMembershipApproverRoles("localhost", 0L).isEmpty());
        }
    }

    @Test
    public void testGetExpiredPendingMembers() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertTrue(fileconnection.getExpiredPendingDomainRoleMembers(30).isEmpty());
        }
    }

    @Test
    public void testDeletePendingRoleMemberInvalidDomain() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.deletePendingRoleMember("", "", "", "", "");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
        }
    }

    @Test
    public void testUpdatePendingRoleMembersNotificationTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertFalse(fileconnection.updatePendingRoleMembersNotificationTimestamp("localhost", 0L, 0));
        }
    }

    @Test
    public void testMatchExpiration() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertTrue(fileconnection.matchExpiration(0, null));
            assertFalse(fileconnection.matchExpiration(10, null));
            assertTrue(fileconnection.matchExpiration(100, Timestamp.fromMillis(100)));
            assertFalse(fileconnection.matchExpiration(101, Timestamp.fromMillis(100)));
        }
    }

    @Test
    public void testUpdateRoleReviewTimestamp() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.updateRoleReviewTimestamp("domain1", "role1");
                fail();
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testGetDomainTemplates() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.getDomainTemplates("domain1");
                fail();
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testupdateDomainTemplate() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        TemplateMetaData templateMetaData = new TemplateMetaData();
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            try {
                fileconnection.updateDomainTemplate("testtemplate", "testdom", templateMetaData);
                fail();
            } catch (Exception ex) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void testgetDomainFromTemplateName() {
        File fileDir = new File("/home/athenz/zms_store");
        File quotaDir = new File("/home/athenz/zms_quota");
        Map<String, Integer> templateVersionMap = new HashMap<>();
        templateVersionMap.put("testtemplate", 1);
        Map<String, List<String>> domainNameTemplateListMap = new HashMap<>();
        try (FileConnection fileconnection = new FileConnection(fileDir, quotaDir)) {
            assertEquals(fileconnection.getDomainFromTemplateName(templateVersionMap), domainNameTemplateListMap);
        }
    }
}

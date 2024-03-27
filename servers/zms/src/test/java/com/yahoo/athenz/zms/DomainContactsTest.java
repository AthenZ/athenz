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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;

public class DomainContactsTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_CONTACT_TYPES, "pe-owner,security-contact,audit-contact,product-owner");
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
        System.clearProperty(ZMSConsts.ZMS_PROP_DOMAIN_CONTACT_TYPES);
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
    }

    @Test
    public void testDomainContacts() {

        final String domainName = "domain-with-contacts";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        Map<String, String> domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.user1");
        domainContacts.put("security-contact", "user.user2");
        domainContacts.put("audit-contact", "");
        dom1.setContacts(domainContacts);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        Map<String, String> domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 2);
        assertEquals(domainContactsRes.get("pe-owner"), "user.user1");
        assertEquals(domainContactsRes.get("security-contact"), "user.user2");

        // now we're going to set the same as part of our meta
        // call and make sure there are no changes

        DomainMeta domainMeta = new DomainMeta().setContacts(domainContacts);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // now let's fetch our domain and verify the contacts

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 2);
        assertEquals(domainContactsRes.get("pe-owner"), "user.user1");
        assertEquals(domainContactsRes.get("security-contact"), "user.user2");

        // this time we're going to add a new contact, update one and then
        // delete one (we're going to delete the security-contact by passing
        // an empty string). the code should also skip new product-owner since
        // it has an empty value

        domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.user2");
        domainContacts.put("audit-contact", "user.user3");
        domainContacts.put("security-contact", "");
        domainContacts.put("product-owner", "");
        domainMeta = new DomainMeta().setContacts(domainContacts);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // now let's fetch our domain and verify the contacts

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 2);
        assertEquals(domainContactsRes.get("pe-owner"), "user.user2");
        assertEquals(domainContactsRes.get("audit-contact"), "user.user3");

        // this time we're going to remove all contacts

        domainMeta = new DomainMeta().setContacts(Collections.emptyMap());
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // now let's fetch our domain and verify no contacts

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertTrue(domainContactsRes.isEmpty());

        // now let's re-add some domain contacts

        domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.user5");
        domainContacts.put("audit-contact", "user.user6");
        domainContacts.put("security-contact", "user.user7");
        domainMeta = new DomainMeta().setContacts(domainContacts);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.user5");
        assertEquals(domainContactsRes.get("audit-contact"), "user.user6");
        assertEquals(domainContactsRes.get("security-contact"), "user.user7");

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testDomainContactsFailures() {

        final String domainName = "domain-with-contacts-failures";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");

        // adding a new contact type of "test-contact" which is not
        // configured should be rejected

        Map<String, String> domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.user1");
        domainContacts.put("test-contact", "user.user2");
        dom1.setContacts(domainContacts);

        try {
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid domain contact type: test-contact"));
        }

        // remove the contacts and add again

        dom1.setContacts(null);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // now let's add the contacts with a valid type through the meta call

        domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.user1");
        DomainMeta domainMeta = new DomainMeta().setContacts(domainContacts);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // now let's fetch our domain and verify the contacts

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        Map<String, String> domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 1);
        assertEquals(domainContactsRes.get("pe-owner"), "user.user1");

        // this time we're going to add with a bad contact type

        domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.user2");
        domainContacts.put("test-contact", "user.user3");
        domainMeta = new DomainMeta().setContacts(domainContacts);

        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid domain contact type: test-contact"));
        }

        // now let's try with a valid contact but invalid username. the test authority
        // only allows user.joe, user.jane and user.jack

        Authority userAuthority = zmsImpl.userAuthority;
        zmsImpl.userAuthority = new TestUserPrincipalAuthority();
        domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.joe");
        domainContacts.put("security-contact", "user.user3");
        domainMeta = new DomainMeta().setContacts(domainContacts);

        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid domain contact: security-contact"));
        }

        // now let's add all three valid users and contacts

        domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.joe");
        domainContacts.put("security-contact", "user.jane");
        domainContacts.put("audit-contact", "user.jack");
        domainMeta = new DomainMeta().setContacts(domainContacts);

        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // reset our authority

        zmsImpl.userAuthority = userAuthority;
        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testUpdateDomainContactsForUserDelete() {

        final String domainName = "user-delete-with-contacts";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        Map<String, String> domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.joe");
        domainContacts.put("security-contact", "user.jane");
        domainContacts.put("audit-contact", "user.jack");
        dom1.setContacts(domainContacts);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        Map<String, String> domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // in our test authority jane is joe's manager
        // and jack is jane's manager
        // jack does not have a manager

        Authority userAuthority = zmsImpl.dbService.zmsConfig.getUserAuthority();
        zmsImpl.dbService.zmsConfig.setUserAuthority(new TestUserPrincipalAuthority());

        // first we're going to delete joe and make sure the pe-owner
        // is set to jane

        zmsImpl.deleteUser(ctx, "joe", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.jane");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // now let's delete jane and make sure the ownership is set to jack

        zmsImpl.deleteUser(ctx, "jane", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.jack");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jack");

        // now let's delete jack and make sure the ownership is set to null

        zmsImpl.deleteUser(ctx, "jack", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertTrue(domainContactsRes.isEmpty());

        zmsImpl.dbService.zmsConfig.setUserAuthority(userAuthority);
        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testUpdateDomainContactsForUserDeleteManagerException() {

        final String domainName = "user-delete-with-contacts";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        Map<String, String> domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.joe");
        domainContacts.put("security-contact", "user.jane");
        domainContacts.put("audit-contact", "user.jack");
        dom1.setContacts(domainContacts);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        Map<String, String> domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // we're going to set our user authority to be null so that
        // when we delete a user there are no changes

        Authority userAuthority = zmsImpl.dbService.zmsConfig.getUserAuthority();
        zmsImpl.dbService.zmsConfig.setUserAuthority(null);

        // first we're going to delete joe and make sure we're going to
        // delete the user entry

        zmsImpl.deleteUser(ctx, "joe", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 2);
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // now we're going to set our authority to throw an exception

        zmsImpl.dbService.zmsConfig.setUserAuthority(new TestUserPrincipalAuthority() {
            @Override
            public String getUserManager(String userName) {
                throw new RuntimeException("invalid manager");
            }
        });

        // now let's delete jane and make sure the entry is removed

        zmsImpl.deleteUser(ctx, "jane", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 1);
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");

        zmsImpl.dbService.zmsConfig.setUserAuthority(userAuthority);
        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testUpdateDomainContactsForUserContactListException() {

        final String domainName = "user-delete-with-contacts";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        Map<String, String> domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.joe");
        domainContacts.put("security-contact", "user.jane");
        domainContacts.put("audit-contact", "user.jack");
        dom1.setContacts(domainContacts);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        Map<String, String> domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // in our test authority jane is joe's manager
        // and jack is jane's manager
        // jack does not have a manager

        Authority userAuthority = zmsImpl.dbService.zmsConfig.getUserAuthority();
        zmsImpl.dbService.zmsConfig.setUserAuthority(new TestUserPrincipalAuthority());

        Map<String, List<String>> contactDomains = new HashMap<>();
        contactDomains.put("sports", List.of("pe-owner"));

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.listContactDomains("user.joe"))
                .thenThrow(new ResourceException(500)).thenReturn(contactDomains);
        Mockito.when(conn.updateDomainContact("sports", "pe-owner", "user.jane"))
                .thenThrow(new ResourceException(500));

        // first we're going to delete joe and make sure we're going to
        // delete the user entry

        zmsImpl.dbService.updateDomainContactReferences(conn, "user.joe");

        // verify there were no changes since we should have received
        // an exception when getting the list

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // now let's call the api second time which will return valid contact domain
        // list but exception when we try to update the domain contact

        zmsImpl.dbService.updateDomainContactReferences(conn, "user.joe");

        // verify there were no changes since we should have received
        // an exception when getting the list

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        zmsImpl.dbService.zmsConfig.setUserAuthority(userAuthority);
        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testUpdateDomainContactsForUserListException() {

        final String domainName = "user-delete-with-contacts";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        Map<String, String> domainContacts = new HashMap<>();
        domainContacts.put("pe-owner", "user.joe");
        domainContacts.put("security-contact", "user.jane");
        domainContacts.put("audit-contact", "user.jack");
        dom1.setContacts(domainContacts);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        Map<String, String> domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 3);
        assertEquals(domainContactsRes.get("pe-owner"), "user.joe");
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // we're going to set our user authority to be null so that
        // when we delete a user there are no changes

        Authority userAuthority = zmsImpl.dbService.zmsConfig.getUserAuthority();
        zmsImpl.dbService.zmsConfig.setUserAuthority(null);

        // first we're going to delete joe and make sure we're going to
        // delete the user entry

        zmsImpl.deleteUser(ctx, "joe", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 2);
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");
        assertEquals(domainContactsRes.get("security-contact"), "user.jane");

        // now we're going to set our authority to throw an exception

        zmsImpl.dbService.zmsConfig.setUserAuthority(new TestUserPrincipalAuthority() {
            @Override
            public String getUserManager(String userName) {
                throw new RuntimeException("invalid manager");
            }
        });

        // now let's delete jane and make sure the entry is removed

        zmsImpl.deleteUser(ctx, "jane", auditRef);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        domainContactsRes = domain.getContacts();
        assertNotNull(domainContactsRes);
        assertEquals(domainContactsRes.size(), 1);
        assertEquals(domainContactsRes.get("audit-contact"), "user.jack");

        zmsImpl.dbService.zmsConfig.setUserAuthority(userAuthority);
        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }
}

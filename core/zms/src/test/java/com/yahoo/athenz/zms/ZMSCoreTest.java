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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;

public class ZMSCoreTest {

    @Test
    public void test() {
        Schema schema = ZMSSchema.instance();
        assertNotNull(schema);
    }

    @Test
    public void testRoles() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> members = Arrays.asList("user.boynton");
        Role r = new Role().setName("sys.auth:role.admin").setMembers(members);
        Result result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("user.boynton"); // new
        r = new Role().setName("sys.auth:role.admin").setMembers(members).setAuditEnabled(true);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("user:doe"); // new
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);

        members = Arrays.asList("sports:role.admin"); // new
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);

        members = Arrays.asList("sports:group.admin"); // valid group member
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("sports:group.admin.test"); // valid group member
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("sports:group.admin-test"); // valid group member
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("sports:group.admin*"); // invalid group member
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);

        members = Arrays.asList("sports:groupadmin.test"); // invalid group member
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);

        members = Arrays.asList("sports:group-admin"); // not valid
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);

        members = Arrays.asList("sports::group.admin"); // not valid
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);

        members = Arrays.asList("someuser@somecompany.com"); // not a valid principal
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);
    }

    @Test
    public void testRoleAuditLog() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // RoleAuditlog test
        RoleAuditLog ral = new RoleAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");
        Result result = validator.validate(ral, "RoleAuditLog");
        assertTrue(result.valid);

        assertEquals(ral.getMember(), "user.test");
        assertEquals(ral.getAdmin(), "user.admin");
        assertEquals(ral.getCreated(), Timestamp.fromMillis(123456789123L));
        assertEquals(ral.getAction(), "add");
        assertEquals(ral.getAuditRef(), "zmstest");

        RoleAuditLog ral2 = new RoleAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");

        assertTrue(ral2.equals(ral));
        assertTrue(ral.equals(ral));

        ral2.setAuditRef(null);
        assertFalse(ral2.equals(ral));
        ral2.setAction(null);
        assertFalse(ral2.equals(ral));
        ral2.setCreated(null);
        assertFalse(ral2.equals(ral));
        ral2.setAdmin(null);
        assertFalse(ral2.equals(ral));
        ral2.setMember(null);
        assertFalse(ral2.equals(ral));
        assertFalse(ral2.equals(new String()));
    }

    @Test
    public void testRoleListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> names = Arrays.asList("test.role");

        RoleList rl = new RoleList().setNames(names).setNext("next");

        Result result = validator.validate(rl, "RoleList");
        assertTrue(result.valid);

        assertEquals(rl.getNames(), names);
        assertEquals(rl.getNext(), "next");

        RoleList rl2 = new RoleList().setNames(names).setNext("next");
        assertTrue(rl2.equals(rl));
        assertTrue(rl.equals(rl));

        rl2.setNext(null);
        assertFalse(rl2.equals(rl));
        rl2.setNames(null);
        assertFalse(rl2.equals(rl));
        assertFalse(rl.equals(new String()));
    }

    @Test
    public void testSignedTokens() {
        String[] signedTokens = { "v=R1;d=domain;s=test;i=127.0.0.1;h=someserver1.somecompany.com;r=role1,role2;s=signature",
                "v=R1;d=domai_-.test;s=test---test;i=2001:db8:85a3:8d3:1319:8a2e:370:7348;h=hostname;r=role1,role2s=signature" };

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        for (String s : signedTokens) {
            Result result = validator.validate(s, "SignedToken");
            assertTrue(result.valid);
        }
    }

    @Test
    public void testResourceNames() {
        String[] goodResources = {
                "domain:role.test1_",
                "domain:role._test1_",
                "domain:role._-test1_",
                "domain:role._-----",
                "domain:role._____",
                "3com:role.3role_-",
                "3com:entity",
                "_domain:3entity_",
                "domain:entity",
                "my.domain:entity",
                "my.domain:entity.path"
        };

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        for (String s : goodResources) {
            Result result = validator.validate(s, "ResourceName");
            assertTrue(result.valid);
        }

        String[] badResources = {
                "domain:role.-----",
                "-domain:role.role1",
                "Non_ascii:��",
                "cannot-start-with:-dash",
                "cannot-use:Punctuation_except_underbar!"
        };

        for (String s : badResources) {
            Result result = validator.validate(s, "ResourceName");
            assertFalse(result.valid);
        }
    }

    @Test
    public void testAssertionMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // assertion test
        Assertion a = new Assertion().setRole("test.role").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);
        Result result = validator.validate(a, "Assertion");
        assertTrue(result.valid);

        assertEquals(a.getRole(), "test.role");
        assertEquals(a.getResource(), "test.resource.*");
        assertEquals(a.getAction(), "test-action");
        assertEquals(a.getEffect(), AssertionEffect.fromString("ALLOW"));
        assertEquals((long) a.getId(), 0L);

        Assertion a2 = new Assertion().setRole("test.role").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);

        assertTrue(a2.equals(a));
        assertTrue(a.equals(a));

        a2.setId(null);
        assertFalse(a2.equals(a));

        a2.setId(0L);
        a2.setEffect(null);
        assertFalse(a2.equals(a));

        a2.setEffect(AssertionEffect.ALLOW);
        a2.setAction(null);
        assertFalse(a2.equals(a));

        a2.setAction("test-action");
        a2.setResource(null);
        assertFalse(a2.equals(a));

        a2.setRole(null);
        a2.setResource("test.resource.*");
        assertFalse(a2.equals(a));
        assertFalse(a.equals(new String()));

        a2.setRole("test.role");

        Map<String, AssertionConditionData> m1 = new HashMap<>();
        AssertionConditionData cd1 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        m1.put("instances", cd1);
        AssertionCondition c1 = new AssertionCondition().setConditionsMap(m1);
        List<AssertionCondition> c1List = Collections.singletonList(c1);
        AssertionConditions assertionConditions1 = new AssertionConditions().setConditionsList(c1List);
        a.setConditions(assertionConditions1);
        assertFalse(a2.equals(a));

        Map<String, AssertionConditionData> m2 = new HashMap<>();
        AssertionConditionData cd2 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        m2.put("instances", cd2);
        AssertionCondition c2 = new AssertionCondition().setConditionsMap(m2);
        List<AssertionCondition> c2List = Collections.singletonList(c2);
        AssertionConditions assertionConditions2 = new AssertionConditions().setConditionsList(c2List);
        a2.setConditions(assertionConditions2);
        assertEquals(a, a2);

        assertEquals(c1, a.getConditions().getConditionsList().get(0));
    }

    @Test
    public void testAssertionMethodCaseSensitive() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // assertion test
        Assertion a = new Assertion().setRole("test.role").setResource("test.ResourcE.*").setAction("Test-ACTION")
                .setEffect(AssertionEffect.ALLOW).setId(0L).setCaseSensitive(true);
        Result result = validator.validate(a, "Assertion");
        assertTrue(result.valid);

        assertEquals(a.getRole(), "test.role");
        assertEquals(a.getResource(), "test.ResourcE.*");
        assertEquals(a.getAction(), "Test-ACTION");
        assertEquals(a.getEffect(), AssertionEffect.fromString("ALLOW"));
        assertEquals((long) a.getId(), 0L);
        assertEquals(a.getCaseSensitive().booleanValue(), true);

        Assertion a2 = new Assertion().setRole("test.role").setResource("test.ResourcE.*").setAction("Test-ACTION")
                .setEffect(AssertionEffect.ALLOW).setId(0L).setCaseSensitive(true);

        assertTrue(a2.equals(a));
        assertTrue(a.equals(a));

        a2.setCaseSensitive(null);
        assertFalse(a2.equals(a));
        a2.setCaseSensitive(false);
        assertFalse(a2.equals(a));
        a2.setId(null);
        assertFalse(a2.equals(a));
        a2.setEffect(null);
        assertFalse(a2.equals(a));
        a2.setAction(null);
        assertFalse(a2.equals(a));
        a2.setResource(null);
        assertFalse(a2.equals(a));
        a2.setRole(null);
        assertFalse(a2.equals(a));
        assertFalse(a.equals(new String()));
    }

    @Test
    public void testSignedDomainsMethod() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Role r = new Role().setName("test.role");
        List<Role> rl = Arrays.asList(r);

        Assertion a = new Assertion().setRole("test.role").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);

        List<Assertion> al = Arrays.asList(a);

        // Policy test
        Policy p = new Policy().setName("test-policy").setModified(Timestamp.fromMillis(123456789123L))
                .setAssertions(al)
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        Result result = validator.validate(p, "Policy");
        assertTrue(result.valid);

        assertEquals(p.getName(), "test-policy");
        assertEquals(p.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(p.getAssertions(), al);

        Policy p2 = new Policy().setName("test-policy").setModified(Timestamp.fromMillis(123456789123L))
                .setAssertions(al)
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue2"))));

        assertFalse(p2.equals(p));
        assertTrue(p.equals(p));

        p2.setName(null);
        assertFalse(p2.equals(p));
        assertFalse(p.equals(p2));
        p2.setName("test-policy-2");
        assertFalse(p2.equals(p));
        assertFalse(p.equals(p2));
        p2.setName("test-policy");

        p2.setModified(null);
        assertFalse(p2.equals(p));
        p2.setModified(Timestamp.fromMillis(123456789124L));
        assertFalse(p2.equals(p));
        p2.setModified(Timestamp.fromMillis(123456789123L));

        p2.setAssertions(null);
        assertFalse(p2.equals(p));
        assertFalse(p.equals(p2));
        p2.setAssertions(Collections.singletonList(new Assertion()));
        assertFalse(p2.equals(p));
        assertFalse(p.equals(p2));
        p2.setAssertions(al);

        p2.setCaseSensitive(true);
        assertFalse(p2.equals(p));
        assertFalse(p.equals(p2));
        p2.setCaseSensitive(null);

        assertEquals(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue2"))), p2.getTags());

        assertFalse(p.equals(new String()));
        assertFalse(p2.equals(null));


        // PublicKeyEntry test
        PublicKeyEntry pke = new PublicKeyEntry().setId("v1").setKey("pubkey====");
        assertTrue(pke.equals(pke));

        result = validator.validate(pke, "PublicKeyEntry");
        assertTrue(result.valid);

        assertEquals(pke.getId(), "v1");
        assertEquals(pke.getKey(), "pubkey====");

        PublicKeyEntry pke2 = new PublicKeyEntry().setId("v1").setKey("pubkey====");
        assertTrue(pke2.equals(pke));

        pke2.setId(null);
        assertFalse(pke2.equals(pke));
        pke2.setId("v1");

        pke2.setKey(null);
        assertFalse(pke2.equals(pke));
        assertFalse(pke.equals(new String()));

        // Entity test
        Entity e = new Entity().setName("test.entity").setValue(new Struct().with("key", "test"));
        assertTrue(e.equals(e));

        assertEquals(e.getName(), "test.entity");
        assertTrue(e.getValue().equals(new Struct().with("key", (Object) "test")));

        Entity e2 = new Entity().setName("test.entity").setValue(new Struct().with("key", "test"));
        assertTrue(e2.equals(e));

        e2.setValue(null);
        assertFalse(e2.equals(e));
        e2.setValue(new Struct().with("key", "test"));
        e2.setName(null);
        assertFalse(e2.equals(e));
        assertFalse(e.equals(new String()));

        List<Policy> pl = Arrays.asList(p);
        // DomainPolicies test
        DomainPolicies dps = new DomainPolicies().setDomain("dps.domain").setPolicies(pl);
        result = validator.validate(dps, "DomainPolicies");
        assertTrue(result.valid);

        assertEquals(dps.getDomain(), "dps.domain");
        assertEquals(dps.getPolicies(), pl);

        DomainPolicies dps2 = new DomainPolicies().setDomain("dps.domain").setPolicies(pl);
        assertTrue(dps2.equals(dps));
        assertTrue(dps.equals(dps));

        dps2.setPolicies(null);
        assertFalse(dps2.equals(dps));
        dps2.setDomain(null);
        assertFalse(dps2.equals(dps));
        assertFalse(dps.equals(new String()));

        // SignedPolicies test
        SignedPolicies sp = new SignedPolicies().setContents(dps).setSignature("zmssignature").setKeyId("v1");
        result = validator.validate(sp, "SignedPolicies");
        assertTrue(result.valid);

        assertEquals(sp.getContents(), dps);
        assertEquals(sp.getSignature(), "zmssignature");
        assertEquals(sp.getKeyId(), "v1");

        SignedPolicies sp2 = new SignedPolicies().setContents(dps).setSignature("zmssignature").setKeyId("v1");
        assertTrue(sp2.equals(sp));

        sp2.setKeyId(null);
        assertFalse(sp2.equals(sp));
        sp2.setKeyId("v1");

        sp2.setSignature(null);
        assertFalse(sp2.equals(sp));
        sp2.setSignature("zmssignature");

        sp2.setContents(null);
        assertFalse(sp2.equals(sp));
        assertFalse(sp.equals(new String()));

        List<PublicKeyEntry> pkel = Arrays.asList(pke);
        List<String> hosts = Arrays.asList("test.host");
        // ServiceIdentity test
        ServiceIdentity si = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test").setGroup("test.group")
                .setDescription("description")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"));
        result = validator.validate(si, "ServiceIdentity");
        assertTrue(result.valid);

        assertEquals(si.getName(), "test.service");
        assertEquals(si.getPublicKeys(), pkel);
        assertEquals(si.getProviderEndpoint(), "http://test.endpoint");
        assertEquals(si.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(si.getExecutable(), "exec/path");
        assertEquals(si.getHosts(), hosts);
        assertEquals(si.getUser(), "user.test");
        assertEquals(si.getGroup(), "test.group");
        assertEquals(si.getDescription(), "description");
        assertEquals(si.getTags().get("tagKey").getList().get(0), "tagValue");
        assertEquals(si.getResourceOwnership(), new ResourceServiceIdentityOwnership().setObjectOwner("TF"));

        ServiceIdentity si2 = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test").setGroup("test.group")
                .setDescription("description")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"));

        assertTrue(si2.equals(si));
        assertTrue(si.equals(si));

        si2.setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("ZTS"));
        assertNotEquals(si2, si);
        si2.setResourceOwnership(null);
        assertNotEquals(si2, si);
        si2.setResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"));
        assertEquals(si2, si);

        si2.setGroup(null);
        assertFalse(si2.equals(si));
        si2.setGroup(si.getGroup());
        assertTrue(si2.equals(si));
        si2.setUser(null);
        assertFalse(si2.equals(si));
        si2.setUser(si.getUser());
        assertTrue(si2.equals(si));
        si2.setHosts(null);
        assertFalse(si2.equals(si));
        si2.setHosts(si.getHosts());
        assertTrue(si2.equals(si));
        si2.setExecutable(null);
        assertFalse(si2.equals(si));
        si2.setExecutable(si.getExecutable());
        assertTrue(si2.equals(si));
        si2.setModified(null);
        assertFalse(si2.equals(si));
        si2.setModified(si.getModified());
        assertTrue(si2.equals(si));
        si2.setProviderEndpoint(null);
        assertFalse(si2.equals(si));
        si2.setProviderEndpoint(si.getProviderEndpoint());
        assertTrue(si2.equals(si));
        si2.setPublicKeys(null);
        assertFalse(si2.equals(si));
        si2.setPublicKeys(si.getPublicKeys());
        assertTrue(si2.equals(si));
        si2.setDescription(null);
        assertFalse(si2.equals(si));
        si2.setDescription(si.getDescription());
        assertTrue(si2.equals(si));
        si2.setName(null);
        assertFalse(si2.equals(si));
        si2.setName(si.getName());
        assertTrue(si2.equals(si));
        si2.setTags(null);
        assertFalse(si2.equals(si));
        si2.setTags(si.getTags());
        assertTrue(si2.equals(si));
        assertFalse(si.equals(new String()));

        List<ServiceIdentity> sil = Arrays.asList(si);

        // ServiceIdentities test
        ServiceIdentities sis = new ServiceIdentities().setList(sil);
        result = validator.validate(sis, "ServiceIdentities");
        assertTrue(result.valid);

        assertEquals(sis.getList(), sil);

        ServiceIdentities sis2 = new ServiceIdentities().setList(sil);
        assertTrue(sis2.equals(sis));
        assertTrue(sis.equals(sis));

        sis2.setList(null);
        assertFalse(sis2.equals(sis));

        assertFalse(sis.equals(null));
        assertFalse(sis.equals(new String()));

        // groups for the domain object

        List<Group> gl =  new ArrayList<>();
        gl.add(new Group().setName("dev-team"));

        // DomainData test
        List<Entity> elist = new ArrayList<>();
        DomainData dd = new DomainData().setName("test.domain").setAccount("aws").setYpmId(1).setRoles(rl)
                .setPolicies(sp).setServices(sil).setEntities(elist).setModified(Timestamp.fromMillis(123456789123L))
                .setEnabled(true).setApplicationId("101").setCertDnsDomain("athenz.cloud")
                .setMemberExpiryDays(30).setServiceExpiryDays(40).setGroupExpiryDays(50)
                .setTokenExpiryMins(300).setRoleCertExpiryMins(120)
                .setServiceCertExpiryMins(150).setDescription("main domain").setOrg("org").setSignAlgorithm("rsa")
                .setUserAuthorityFilter("OnShore").setGroups(gl).setAzureSubscription("azure").setGcpProject("gcp")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProjectNumber("1235")
                .setProductId("abcd-1234").setFeatureFlags(3).setContacts(Map.of("pe-owner", "user.test"))
                .setEnvironment("production").setResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF"));

        result = validator.validate(dd, "DomainData");
        assertTrue(result.valid, result.error);

        assertEquals(dd.getName(), "test.domain");
        assertEquals(dd.getAccount(), "aws");
        assertEquals(dd.getAzureSubscription(), "azure");
        assertEquals(dd.getGcpProject(), "gcp");
        assertEquals(dd.getGcpProjectNumber(), "1235");
        assertEquals((int) dd.getYpmId(), 1);
        assertEquals(dd.getRoles(), rl);
        assertEquals(dd.getGroups(), gl);
        assertEquals(dd.getPolicies(), sp);
        assertEquals(dd.getServices(), sil);
        assertEquals(dd.getEntities(), elist);
        assertEquals(dd.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals("101", dd.getApplicationId());
        assertTrue(dd.getEnabled());
        assertEquals(dd.getCertDnsDomain(), "athenz.cloud");
        assertFalse(dd.getAuditEnabled());
        assertEquals(dd.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(dd.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(dd.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(dd.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(dd.getRoleCertExpiryMins(), Integer.valueOf(120));
        assertEquals(dd.getServiceCertExpiryMins(), Integer.valueOf(150));
        assertEquals(dd.getDescription(), "main domain");
        assertEquals(dd.getOrg(), "org");
        assertEquals(dd.getSignAlgorithm(), "rsa");
        assertEquals(dd.getUserAuthorityFilter(), "OnShore");
        assertEquals(dd.getTags(),
            Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(dd.getBusinessService(), "business-service");
        assertEquals(dd.getMemberPurgeExpiryDays(), 10);
        assertEquals(dd.getProductId(), "abcd-1234");
        assertEquals(dd.getFeatureFlags(), 3);
        assertEquals(dd.getContacts(), Map.of("pe-owner", "user.test"));
        assertEquals(dd.getEnvironment(), "production");
        assertEquals(dd.getResourceOwnership(), new ResourceDomainOwnership().setObjectOwner("TF"));

        DomainData dd2 = new DomainData().setName("test.domain").setAccount("aws").setYpmId(1).setRoles(rl)
                .setPolicies(sp).setServices(sil).setEntities(elist).setModified(Timestamp.fromMillis(123456789123L))
                .setEnabled(true).setApplicationId("101").setCertDnsDomain("athenz.cloud").setAuditEnabled(false)
                .setMemberExpiryDays(30).setTokenExpiryMins(300).setRoleCertExpiryMins(120).setServiceCertExpiryMins(150)
                .setDescription("main domain").setOrg("org").setSignAlgorithm("rsa").setServiceExpiryDays(40)
                .setUserAuthorityFilter("OnShore").setGroupExpiryDays(50).setGroups(gl).setAzureSubscription("azure")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setBusinessService("business-service").setMemberPurgeExpiryDays(10).setGcpProject("gcp")
                .setGcpProjectNumber("1235").setProductId("abcd-1234").setFeatureFlags(3)
                .setContacts(Map.of("pe-owner", "user.test")).setEnvironment("production")
                .setResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF"));

        assertEquals(dd2, dd);
        assertNotEquals(dd, null);
        assertNotEquals(new String(), dd);

        List<Group> gl2 = new ArrayList<>();
        gl2.add(new Group().setName("new-name"));
        dd2.setGroups(gl2);
        assertNotEquals(dd, dd2);
        dd2.setGroups(null);
        assertNotEquals(dd, dd2);
        dd2.setGroups(gl);
        assertEquals(dd, dd2);

        dd2.setEnvironment("staging");
        assertNotEquals(dd, dd2);
        dd2.setEnvironment(null);
        assertNotEquals(dd, dd2);
        dd2.setEnvironment("production");
        assertEquals(dd, dd2);

        dd2.setContacts(Map.of("product-owner", "user.test"));
        assertNotEquals(dd, dd2);
        dd2.setContacts(null);
        assertNotEquals(dd, dd2);
        dd2.setContacts(Map.of("pe-owner", "user.test"));
        assertEquals(dd, dd2);

        dd2.setName("test.domain2");
        assertNotEquals(dd, dd2);
        dd2.setName(null);
        assertNotEquals(dd, dd2);
        dd2.setName("test.domain");
        assertEquals(dd, dd2);

        dd2.setProductId("abcd-1235");
        assertNotEquals(dd, dd2);
        dd2.setProductId(null);
        assertNotEquals(dd, dd2);
        dd2.setProductId("abcd-1234");
        assertEquals(dd, dd2);

        dd2.setAccount("aws2");
        assertNotEquals(dd, dd2);
        dd2.setAccount(null);
        assertNotEquals(dd, dd2);
        dd2.setAccount("aws");
        assertEquals(dd, dd2);

        dd2.setAzureSubscription("azure2");
        assertNotEquals(dd, dd2);
        dd2.setAzureSubscription(null);
        assertNotEquals(dd, dd2);
        dd2.setAzureSubscription("azure");
        assertEquals(dd, dd2);

        dd2.setGcpProject("gcp2");
        assertNotEquals(dd, dd2);
        dd2.setGcpProject(null);
        assertNotEquals(dd, dd2);
        dd2.setGcpProject("gcp");
        assertEquals(dd, dd2);

        dd2.setGcpProjectNumber("12356");
        assertNotEquals(dd, dd2);
        dd2.setGcpProjectNumber(null);
        assertNotEquals(dd, dd2);
        dd2.setGcpProjectNumber("1235");
        assertEquals(dd, dd2);

        dd2.setUserAuthorityFilter("NotOnShore");
        assertNotEquals(dd, dd2);
        dd2.setUserAuthorityFilter(null);
        assertNotEquals(dd, dd2);
        dd2.setUserAuthorityFilter("OnShore");
        assertEquals(dd, dd2);

        dd2.setSignAlgorithm("ec");
        assertNotEquals(dd, dd2);
        dd2.setSignAlgorithm(null);
        assertNotEquals(dd, dd2);
        dd2.setSignAlgorithm("rsa");
        assertEquals(dd, dd2);

        dd2.setMemberExpiryDays(45);
        assertNotEquals(dd, dd2);
        dd2.setMemberExpiryDays(null);
        assertNotEquals(dd, dd2);
        dd2.setMemberExpiryDays(30);
        assertEquals(dd, dd2);

        dd2.setMemberPurgeExpiryDays(45);
        assertNotEquals(dd, dd2);
        dd2.setMemberPurgeExpiryDays(null);
        assertNotEquals(dd, dd2);
        dd2.setMemberPurgeExpiryDays(10);
        assertEquals(dd, dd2);

        dd2.setServiceExpiryDays(45);
        assertNotEquals(dd, dd2);
        dd2.setServiceExpiryDays(null);
        assertNotEquals(dd, dd2);
        dd2.setServiceExpiryDays(40);
        assertEquals(dd, dd2);

        dd2.setGroupExpiryDays(55);
        assertNotEquals(dd, dd2);
        dd2.setGroupExpiryDays(null);
        assertNotEquals(dd, dd2);
        dd2.setGroupExpiryDays(50);
        assertEquals(dd, dd2);

        dd2.setTokenExpiryMins(450);
        assertNotEquals(dd, dd2);
        dd2.setTokenExpiryMins(null);
        assertNotEquals(dd, dd2);
        dd2.setTokenExpiryMins(300);
        assertEquals(dd, dd2);

        dd2.setRoleCertExpiryMins(130);
        assertNotEquals(dd, dd2);
        dd2.setRoleCertExpiryMins(null);
        assertNotEquals(dd, dd2);
        dd2.setRoleCertExpiryMins(120);
        assertEquals(dd, dd2);

        dd2.setServiceCertExpiryMins(160);
        assertNotEquals(dd, dd2);
        dd2.setServiceCertExpiryMins(null);
        assertNotEquals(dd, dd2);
        dd2.setServiceCertExpiryMins(150);
        assertEquals(dd, dd2);

        dd2.setFeatureFlags(7);
        assertNotEquals(dd, dd2);
        dd2.setFeatureFlags(null);
        assertNotEquals(dd, dd2);
        dd2.setFeatureFlags(3);
        assertEquals(dd, dd2);

        dd2.setDescription("new domain");
        assertNotEquals(dd, dd2);
        dd2.setDescription(null);
        assertNotEquals(dd, dd2);
        dd2.setDescription("main domain");
        assertEquals(dd, dd2);

        dd2.setOrg("new org");
        assertNotEquals(dd, dd2);
        dd2.setOrg(null);
        assertNotEquals(dd, dd2);
        dd2.setOrg("org");
        assertEquals(dd, dd2);

        dd2.setTags(Collections.singletonMap("tagKeyOther", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertNotEquals(dd, dd2);
        dd2.setTags(null);
        assertNotEquals(dd, dd2);
        dd2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(dd, dd2);

        dd2.setBusinessService("business-service2");
        assertNotEquals(dd, dd2);
        dd2.setBusinessService(null);
        assertNotEquals(dd, dd2);
        dd2.setBusinessService("business-service");
        assertEquals(dd, dd2);

        dd2.setResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF2"));
        assertNotEquals(dd, dd2);
        dd2.setResourceOwnership(null);
        assertNotEquals(dd, dd2);
        dd2.setResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF"));
        assertEquals(dd, dd2);

        dd2.setAuditEnabled(true);
        assertNotEquals(dd, dd2);
        dd2.setAuditEnabled(null);
        assertNotEquals(dd, dd2);

        dd2.setAuditEnabled(false);
        assertEquals(dd, dd2);

        dd2.setCertDnsDomain(null);
        assertNotEquals(dd, dd2);

        dd2.setCertDnsDomain("athenz.cloud");
        dd2.setApplicationId(null);
        assertNotEquals(dd, dd2);

        dd2.setApplicationId("101");
        dd2.setModified(null);
        assertNotEquals(dd, dd2);

        dd2.setModified(Timestamp.fromMillis(123456789123L));
        dd2.setEntities(null);
        assertNotEquals(dd, dd2);

        dd2.setEntities(elist);
        dd2.setServices(null);
        assertNotEquals(dd, dd2);

        dd2.setServices(sil);
        dd2.setPolicies(null);
        assertNotEquals(dd, dd2);

        dd2.setPolicies(sp);
        dd2.setRoles(null);
        assertNotEquals(dd, dd2);

        dd2.setRoles(rl);
        dd2.setEnabled(false);
        assertNotEquals(dd, dd2);
        dd2.setEnabled(null);
        assertNotEquals(dd, dd2);

        dd2.setEnabled(true);
        dd2.setYpmId(null);
        assertNotEquals(dd, dd2);

        dd2.setYpmId(1);
        dd2.setAccount(null);
        assertNotEquals(dd, dd2);

        // SignedDomain test
        SignedDomain sd = new SignedDomain().setDomain(dd).setSignature("zmssignature").setKeyId("v1");
        result = validator.validate(sd, "SignedDomain");
        assertTrue(result.valid);

        assertEquals(sd.getDomain(), dd);
        assertEquals(sd.getSignature(), "zmssignature");
        assertEquals(sd.getKeyId(), "v1");

        SignedDomain sd2 = new SignedDomain().setDomain(dd).setSignature("zmssignature").setKeyId("v1");
        assertEquals(sd, sd2);
        assertEquals(sd, sd);

        sd2.setKeyId(null);
        assertNotEquals(sd, sd2);
        sd2.setSignature(null);
        assertNotEquals(sd, sd2);
        sd2.setDomain(null);
        assertNotEquals(sd, sd2);
        assertNotEquals(new String(), sd);

        List<SignedDomain> sdl = List.of(sd);

        // SignedDomains test
        SignedDomains sds1 = new SignedDomains().setDomains(sdl);
        result = validator.validate(sds1, "SignedDomains");
        assertTrue(result.valid);

        assertEquals(sds1.getDomains(), sdl);

        SignedDomains sds2 = new SignedDomains().setDomains(sdl);
        assertEquals(sds1, sds2);
        assertEquals(sds1, sds1);

        sds2.setDomains(null);
        assertNotEquals(sds1, sds2);

        assertNotEquals(sds1, null);
        assertNotEquals(new String(), sds1);
    }

    @Test
    public void testAccess() {

        Access a = new Access().setGranted(true);
        assertEquals(a.getGranted(), true);
        assertTrue(a.equals(a));

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(a, "Access");
        assertTrue(result.valid);

        Access a2 = new Access().setGranted(false);
        assertFalse(a2.equals(a));

        a2.setGranted(true);
        assertTrue(a2.equals(a));

        assertFalse(a.equals(new String()));
    }

    @Test(expectedExceptions = { java.lang.IllegalArgumentException.class })
    public void testAssertionEffectExcept() {
        AssertionEffect.fromString("INVALID EFFECT");
    }

    @Test
    public void testDomainDataCheckMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> dlrl = Arrays.asList("test.role");

        // DanglingPolicy test
        DanglingPolicy dlp = new DanglingPolicy().setPolicyName("test.policy").setRoleName("test.role");
        Result result = validator.validate(dlp, "DanglingPolicy");
        assertTrue(result.valid);

        assertEquals(dlp.getPolicyName(), "test.policy");
        assertEquals(dlp.getRoleName(), "test.role");

        DanglingPolicy dlp2 = new DanglingPolicy().setPolicyName("test.policy").setRoleName("test.role");
        assertTrue(dlp2.equals(dlp));
        assertTrue(dlp.equals(dlp));

        dlp2.setRoleName(null);
        assertFalse(dlp2.equals(dlp));
        dlp2.setPolicyName(null);
        assertFalse(dlp2.equals(dlp));

        assertFalse(dlp.equals(null));
        assertFalse(dlp.equals(new String()));

        List<DanglingPolicy> dlpl = Arrays.asList(dlp);
        List<String> pwt = Arrays.asList("provider.without.trust");
        List<String> twar = Arrays.asList("tenants.without.assume.role");

        DomainDataCheck ddc = new DomainDataCheck().setDanglingRoles(dlrl).setDanglingPolicies(dlpl).setPolicyCount(10)
                .setAssertionCount(10).setRoleWildCardCount(10).setProvidersWithoutTrust(pwt)
                .setTenantsWithoutAssumeRole(twar);
        result = validator.validate(ddc, "DomainDataCheck");
        assertTrue(result.valid);

        assertEquals(ddc.getDanglingRoles(), dlrl);
        assertEquals(ddc.getDanglingPolicies(), dlpl);
        assertEquals(ddc.getPolicyCount(), 10);
        assertEquals(ddc.getProvidersWithoutTrust(), pwt);
        assertEquals(ddc.getTenantsWithoutAssumeRole(), twar);
        assertEquals(ddc.getAssertionCount(), 10);
        assertEquals(ddc.getRoleWildCardCount(), 10);

        DomainDataCheck ddc2 = new DomainDataCheck().setDanglingRoles(dlrl).setDanglingPolicies(dlpl).setPolicyCount(10)
                .setAssertionCount(10).setRoleWildCardCount(10).setProvidersWithoutTrust(pwt)
                .setTenantsWithoutAssumeRole(twar);

        assertTrue(ddc.equals(ddc));
        assertTrue(ddc2.equals(ddc));

        ddc2.setTenantsWithoutAssumeRole(null);
        assertFalse(ddc2.equals(ddc));
        ddc2.setProvidersWithoutTrust(null);
        assertFalse(ddc2.equals(ddc));
        ddc2.setRoleWildCardCount(11);
        assertFalse(ddc2.equals(ddc));
        ddc2.setAssertionCount(11);
        assertFalse(ddc2.equals(ddc));
        ddc2.setPolicyCount(11);
        assertFalse(ddc2.equals(ddc));
        ddc2.setDanglingPolicies(null);
        assertFalse(ddc2.equals(ddc));
        ddc2.setDanglingRoles(null);
        assertFalse(ddc2.equals(ddc));
        assertFalse(ddc2.equals(null));

    }

    @Test
    public void testDefaultAdmins() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> admins = Arrays.asList("user.admin");

        DefaultAdmins da = new DefaultAdmins().setAdmins(admins);
        Result result = validator.validate(da, "DefaultAdmins");
        assertTrue(result.valid);

        assertEquals(da.getAdmins(), admins);

        DefaultAdmins da2 = new DefaultAdmins().setAdmins(Arrays.asList("user.admin2"));
        assertTrue(da.equals(da));

        da2.setAdmins(null);
        assertFalse(da2.equals(da));
        assertFalse(da2.equals(null));
    }

    @Test
    public void testRoleMember() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        RoleMember rm = new RoleMember()
                .setMemberName("user.test1")
                .setExpiration(Timestamp.fromMillis(123456789123L))
                .setAuditRef("audit-ref")
                .setActive(false)
                .setApproved(true)
                .setRequestTime(Timestamp.fromMillis(123456789124L))
                .setLastNotifiedTime(Timestamp.fromMillis(123456789125L))
                .setRequestPrincipal("user.admin")
                .setReviewReminder(Timestamp.fromMillis(123456789126L))
                .setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L))
                .setSystemDisabled(1)
                .setPrincipalType(1)
                .setPendingState("ADD");

        assertTrue(rm.equals(rm));

        Result result = validator.validate(rm, "RoleMember");
        assertTrue(result.valid);

        assertEquals(rm.getMemberName(), "user.test1");
        assertEquals(rm.getExpiration().millis(), 123456789123L);
        assertEquals(rm.getAuditRef(), "audit-ref");
        assertFalse(rm.getActive());
        assertTrue(rm.getApproved());
        assertEquals(rm.getRequestTime().millis(), 123456789124L);
        assertEquals(rm.getLastNotifiedTime().millis(), 123456789125L);
        assertEquals(rm.getRequestPrincipal(), "user.admin");
        assertEquals(rm.getReviewReminder().millis(), 123456789126L);
        assertEquals(rm.getReviewLastNotifiedTime().millis(), 123456789127L);
        assertEquals(rm.getSystemDisabled(), Integer.valueOf(1));
        assertEquals(rm.getPrincipalType(), Integer.valueOf(1));
        assertEquals(rm.getPendingState(), "ADD");

        RoleMember rm2 = new RoleMember()
                .setMemberName("user.test1")
                .setExpiration(Timestamp.fromMillis(123456789123L))
                .setAuditRef("audit-ref")
                .setActive(false)
                .setApproved(true)
                .setRequestTime(Timestamp.fromMillis(123456789124L))
                .setLastNotifiedTime(Timestamp.fromMillis(123456789125L))
                .setRequestPrincipal("user.admin")
                .setReviewReminder(Timestamp.fromMillis(123456789126L))
                .setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L))
                .setSystemDisabled(1)
                .setPrincipalType(1)
                .setPendingState("ADD");
        assertTrue(rm2.equals(rm));

        rm2.setRequestPrincipal("user.test2");
        assertFalse(rm2.equals(rm));
        rm2.setRequestPrincipal(null);
        assertFalse(rm2.equals(rm));
        rm2.setRequestPrincipal("user.admin");
        assertTrue(rm2.equals(rm));

        rm2.setMemberName("user.test2");
        assertFalse(rm2.equals(rm));
        rm2.setMemberName(null);
        assertFalse(rm2.equals(rm));
        rm2.setMemberName("user.test1");
        assertTrue(rm2.equals(rm));

        rm2.setExpiration(Timestamp.fromMillis(123456789124L));
        assertFalse(rm2.equals(rm));
        rm2.setExpiration(null);
        assertFalse(rm2.equals(rm));
        rm2.setExpiration(Timestamp.fromMillis(123456789123L));
        assertTrue(rm2.equals(rm));

        rm2.setRequestTime(Timestamp.fromMillis(123456789125L));
        assertFalse(rm2.equals(rm));
        rm2.setRequestTime(null);
        assertFalse(rm2.equals(rm));
        rm2.setRequestTime(Timestamp.fromMillis(123456789124L));
        assertTrue(rm2.equals(rm));

        rm2.setLastNotifiedTime(Timestamp.fromMillis(123456789128L));
        assertFalse(rm2.equals(rm));
        rm2.setLastNotifiedTime(null);
        assertFalse(rm2.equals(rm));
        rm2.setLastNotifiedTime(Timestamp.fromMillis(123456789125L));
        assertTrue(rm2.equals(rm));

        rm2.setAuditRef("audit2-ref");
        assertFalse(rm2.equals(rm));
        rm2.setAuditRef(null);
        assertFalse(rm2.equals(rm));
        rm2.setAuditRef("audit-ref");
        assertTrue(rm2.equals(rm));

        rm2.setActive(true);
        assertFalse(rm2.equals(rm));
        rm2.setActive(null);
        assertFalse(rm2.equals(rm));
        rm2.setActive(false);
        assertTrue(rm2.equals(rm));

        rm2.setApproved(false);
        assertFalse(rm2.equals(rm));
        rm2.setApproved(null);
        assertFalse(rm2.equals(rm));
        rm2.setApproved(true);
        assertTrue(rm2.equals(rm));

        rm2.setReviewReminder(Timestamp.fromMillis(123456789129L));
        assertFalse(rm2.equals(rm));
        rm2.setReviewReminder(null);
        assertFalse(rm2.equals(rm));
        rm2.setReviewReminder(Timestamp.fromMillis(123456789126L));
        assertTrue(rm2.equals(rm));

        rm2.setReviewLastNotifiedTime(Timestamp.fromMillis(123456789124L));
        assertFalse(rm2.equals(rm));
        rm2.setReviewLastNotifiedTime(null);
        assertFalse(rm2.equals(rm));
        rm2.setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L));
        assertTrue(rm2.equals(rm));

        rm2.setSystemDisabled(2);
        assertFalse(rm2.equals(rm));
        rm2.setSystemDisabled(null);
        assertFalse(rm2.equals(rm));
        rm2.setSystemDisabled(1);
        assertTrue(rm2.equals(rm));

        rm2.setPrincipalType(2);
        assertFalse(rm2.equals(rm));
        rm2.setPrincipalType(null);
        assertFalse(rm2.equals(rm));
        rm2.setPrincipalType(1);
        assertTrue(rm2.equals(rm));

        rm2.setPendingState("DELETE");
        assertFalse(rm2.equals(rm));
        rm2.setPendingState(null);
        assertFalse(rm2.equals(rm));
        rm2.setPendingState("ADD");
        assertTrue(rm2.equals(rm));

        assertFalse(rm2.equals(null));

        RoleMember rm3 = new RoleMember();
        rm3.init();
        assertTrue(rm3.getActive());
        assertTrue(rm3.getApproved());

        rm3.setActive(false);
        rm3.setApproved(false);
        rm3.init();
        assertFalse(rm3.getActive());
        assertFalse(rm3.getApproved());
    }

    @Test
    public void testStatus() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Status st = new Status().setCode(101).setMessage("ok");
        assertTrue(st.equals(st));

        Result result = validator.validate(st, "Status");
        assertTrue(result.valid);

        assertEquals(st.getCode(), 101);
        assertEquals(st.getMessage(), "ok");

        Status st2 = new Status().setCode(1020);
        assertFalse(st2.equals(st));

        st2.setCode(101);
        assertFalse(st2.equals(st));

        st2.setMessage("failed");
        assertFalse(st2.equals(st));
        st2.setMessage("ok");
        assertTrue(st2.equals(st));

        assertFalse(st2.equals(null));
    }

    @Test
    public void testTemplateParam() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        TemplateParam tp = new TemplateParam().setName("name").setValue("service");
        assertTrue(tp.equals(tp));

        Result result = validator.validate(tp, "TemplateParam");
        assertTrue(result.valid);

        assertEquals(tp.getName(), "name");
        assertEquals(tp.getValue(), "service");

        TemplateParam tp2 = new TemplateParam();
        assertFalse(tp2.equals(tp));

        tp2.setName("name2");
        assertFalse(tp2.equals(tp));

        tp2.setName("name");
        assertFalse(tp2.equals(tp));

        tp2.setValue("value2");
        assertFalse(tp2.equals(tp));
        tp2.setValue("service");
        assertTrue(tp2.equals(tp));

        assertFalse(tp2.equals(null));
    }

    @Test
    public void testDomainMetaList() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // DomainModifiedList test
        Domain dm = new Domain().setName("athenz");
        List<Domain> dml = Arrays.asList(dm);

        DomainMetaList dmlist = new DomainMetaList().setDomains(dml);
        Result result = validator.validate(dmlist, "DomainMetaList");
        assertTrue(result.valid);

        assertEquals(dmlist.getDomains(), dml);

        DomainMetaList dmlist2 = new DomainMetaList().setDomains(dml);
        assertTrue(dmlist2.equals(dmlist));
        assertTrue(dmlist.equals(dmlist));

        dmlist2.setDomains(null);
        assertFalse(dmlist2.equals(dmlist));

        assertFalse(dmlist.equals(null));
        assertFalse(dmlist.equals(new String()));
    }

    @Test
    public void testMembershipMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Membership ms = new Membership().init();
        assertTrue(ms.getIsMember());
        assertTrue(ms.getActive());
        assertTrue(ms.getApproved());

        ms.setMemberName("test.member").setIsMember(false).setRoleName("test.role")
                .setExpiration(Timestamp.fromMillis(100)).setAuditRef("audit-ref")
                .setActive(true).setApproved(false).setRequestPrincipal("user.admin")
                .setReviewReminder(Timestamp.fromMillis(200)).setSystemDisabled(1)
                .setPendingState("ADD");

        // init second time does not change state
        ms.init();
        assertFalse(ms.getIsMember());
        assertTrue(ms.getActive());
        assertFalse(ms.getApproved());

        Result result = validator.validate(ms, "Membership");
        assertTrue(result.valid);

        assertEquals(ms.getMemberName(), "test.member");
        assertFalse(ms.getIsMember());
        assertEquals(ms.getRoleName(), "test.role");
        assertEquals(ms.getExpiration(), Timestamp.fromMillis(100));
        assertTrue(ms.getActive());
        assertFalse(ms.getApproved());
        assertEquals(ms.getAuditRef(), "audit-ref");
        assertEquals(ms.getRequestPrincipal(), "user.admin");
        assertEquals(ms.getReviewReminder(), Timestamp.fromMillis(200));
        assertEquals(ms.getSystemDisabled(), Integer.valueOf(1));
        assertEquals(ms.getPendingState(), "ADD");

        Membership ms2 = new Membership().setMemberName("test.member").setIsMember(false)
                .setExpiration(Timestamp.fromMillis(100)).setRoleName("test.role")
                .setActive(true).setAuditRef("audit-ref").setApproved(false)
                .setRequestPrincipal("user.admin").setReviewReminder(Timestamp.fromMillis(200))
                .setSystemDisabled(1).setPendingState("ADD");

        assertTrue(ms2.equals(ms));
        assertTrue(ms.equals(ms));

        ms2.setRequestPrincipal("user.test2");
        assertFalse(ms2.equals(ms));
        ms2.setRequestPrincipal(null);
        assertFalse(ms2.equals(ms));
        ms2.setRequestPrincipal("user.admin");
        assertTrue(ms2.equals(ms));

        ms2.setExpiration(null);
        assertFalse(ms2.equals(ms));
        ms2.setExpiration(Timestamp.fromMillis(100));
        assertTrue(ms2.equals(ms));

        ms2.setRoleName(null);
        assertFalse(ms2.equals(ms));
        ms2.setRoleName("test.role");
        assertTrue(ms2.equals(ms));

        ms2.setIsMember(null);
        assertFalse(ms2.equals(ms));
        ms2.setIsMember(false);
        assertTrue(ms2.equals(ms));

        ms2.setMemberName(null);
        assertFalse(ms2.equals(ms));
        ms2.setMemberName("test.member");
        assertTrue(ms2.equals(ms));

        ms2.setAuditRef(null);
        assertFalse(ms2.equals(ms));
        ms2.setAuditRef("audit-ref");
        assertTrue(ms2.equals(ms));

        ms2.setActive(null);
        assertFalse(ms2.equals(ms));
        ms2.setActive(true);
        assertTrue(ms2.equals(ms));

        ms2.setApproved(null);
        assertFalse(ms2.equals(ms));
        ms2.setApproved(true);
        assertFalse(ms2.equals(ms));
        ms2.setApproved(false);
        assertTrue(ms2.equals(ms));

        ms2.setReviewReminder(Timestamp.fromMillis(300));
        assertFalse(ms2.equals(ms));
        ms2.setReviewReminder(null);
        assertFalse(ms2.equals(ms));
        ms2.setReviewReminder(Timestamp.fromMillis(200));
        assertTrue(ms2.equals(ms));

        ms2.setSystemDisabled(2);
        assertFalse(ms2.equals(ms));
        ms2.setSystemDisabled(null);
        assertFalse(ms2.equals(ms));
        ms2.setSystemDisabled(1);
        assertTrue(ms2.equals(ms));

        ms2.setPendingState("DELETE");
        assertFalse(ms2.equals(ms));
        ms2.setPendingState(null);
        assertFalse(ms2.equals(ms));
        ms2.setPendingState("ADD");
        assertTrue(ms2.equals(ms));

        assertFalse(ms2.equals(null));
        assertFalse(ms.equals(new String()));
    }

    @Test
    public void testDefaultAdminsMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> dal = Arrays.asList("user.admin1");

        DefaultAdmins da = new DefaultAdmins().setAdmins(dal);

        Result result = validator.validate(da, "DefaultAdmins");
        assertTrue(result.valid);

        assertEquals(da.getAdmins(), dal);

        DefaultAdmins da2 = new DefaultAdmins().setAdmins(dal);
        assertTrue(da2.equals(da));
        assertTrue(da.equals(da));

        da2.setAdmins(null);
        assertFalse(da.equals(da2));
        assertFalse(da.equals(null));
    }

    @Test
    public void testPolicyListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> plist = Arrays.asList("test.policy");

        PolicyList pl = new PolicyList().setNames(plist).setNext("next");

        Result result = validator.validate(pl, "PolicyList");
        assertTrue(result.valid);

        assertEquals(pl.getNames(), plist);
        assertEquals(pl.getNext(), "next");

        PolicyList pl2 = new PolicyList().setNames(plist).setNext("next");
        assertTrue(pl2.equals(pl));
        assertTrue(pl.equals(pl));

        pl2.setNext(null);
        assertFalse(pl2.equals(pl));
        pl2.setNames(null);
        assertFalse(pl2.equals(pl));
        assertFalse(pl2.equals(null));
    }

    @Test
    public void testPolicyOptions() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        PolicyOptions policyOptions = new PolicyOptions();
        policyOptions.setFromVersion("from-version");
        policyOptions.setVersion("testversion");
        Result result = validator.validate(policyOptions, "PolicyOptions");
        assertTrue(result.valid);

        assertEquals(policyOptions.getFromVersion(), "from-version");
        assertEquals(policyOptions.getVersion(), "testversion");

        PolicyOptions policyOptions2 = new PolicyOptions();
        policyOptions2.setFromVersion("from-version");
        policyOptions2.setVersion("testversion");

        assertEquals(policyOptions, policyOptions2);
        policyOptions2.setFromVersion(null);
        assertFalse(policyOptions.equals(policyOptions2));
        policyOptions.setFromVersion(null);
        assertTrue(policyOptions.equals(policyOptions2));
        policyOptions2.setVersion(null);
        assertFalse(policyOptions.equals(policyOptions2));
        policyOptions.setVersion(null);
        assertTrue(policyOptions.equals(policyOptions2));
        assertFalse(policyOptions.equals(null));
    }

    @Test
    public void testServiceIdentityListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> slist = Arrays.asList("test.service");

        ServiceIdentityList sil = new ServiceIdentityList().setNames(slist).setNext("next");

        Result result = validator.validate(sil, "ServiceIdentityList");
        assertTrue(result.valid);

        assertEquals(sil.getNames(), slist);
        assertEquals(sil.getNext(), "next");

        ServiceIdentityList sil2 = new ServiceIdentityList().setNames(slist).setNext("next");
        assertTrue(sil2.equals(sil));
        assertTrue(sil.equals(sil));

        sil2.setNext(null);
        assertFalse(sil2.equals(sil));

        sil2.setNames(null);
        assertFalse(sil2.equals(sil));
        assertFalse(sil2.equals(null));
        assertFalse(sil.equals(new String()));
    }

    @Test
    public void testTemplateListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> tnames = Arrays.asList("testtemplate");

        TemplateList tl = new TemplateList().setTemplateNames(tnames);

        Result result = validator.validate(tl, "TemplateList");
        assertTrue(result.valid);

        assertEquals(tl.getTemplateNames(), tnames);

        TemplateList tl2 = new TemplateList().setTemplateNames(tnames);
        assertTrue(tl2.equals(tl));
        assertTrue(tl.equals(tl));

        tl2.setTemplateNames(Arrays.asList("testtemplate2"));
        assertFalse(tl2.equals(tl));

        tl2.setTemplateNames(null);
        assertFalse(tl2.equals(tl));

        assertFalse(tl.equals(null));
        assertFalse(tl.equals(new String()));
    }

    @Test
    public void testDomainTemplateListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> tnames = Arrays.asList("testtemplate");

        DomainTemplate tl = new DomainTemplate().setTemplateNames(tnames);

        Result result = validator.validate(tl, "DomainTemplate");
        assertTrue(result.valid);

        assertEquals(tl.getTemplateNames(), tnames);

        DomainTemplate tl2 = new DomainTemplate().setTemplateNames(tnames);
        assertTrue(tl2.equals(tl));
        assertTrue(tl.equals(tl));

        tl2.setTemplateNames(null);
        assertFalse(tl2.equals(tl));

        assertFalse(tl.equals(null));
        assertFalse(tl.equals(new String()));


        // DomainTemplateList test
        List<String> templateNames = Arrays.asList("test");
        DomainTemplateList dtl = new DomainTemplateList().setTemplateNames(templateNames);

        result = validator.validate(dtl, "DomainTemplateList");
        assertTrue(result.valid);

        DomainTemplateList dtl2 = new DomainTemplateList().setTemplateNames(templateNames);
        assertTrue(dtl2.equals(dtl));
        assertTrue(dtl.equals(dtl));

        dtl2.setTemplateNames(null);
        assertFalse(dtl2.equals(dtl));

        assertFalse(dtl.equals(null));
        assertFalse(dtl.equals(new String()));
    }

    @Test
    public void testServerTemplateListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> tnames = Arrays.asList("testtemplate");

        ServerTemplateList tl1 = new ServerTemplateList().setTemplateNames(tnames);

        Result result = validator.validate(tl1, "ServerTemplateList");
        assertTrue(result.valid);

        assertEquals(tl1.getTemplateNames(), tnames);

        ServerTemplateList tl2 = new ServerTemplateList().setTemplateNames(tnames);
        assertTrue(tl2.equals(tl1));
        assertTrue(tl1.equals(tl1));

        tl2.setTemplateNames(null);
        assertFalse(tl2.equals(tl1));

        assertFalse(tl1.equals(null));
        assertFalse(tl1.equals(new String()));
    }

    @Test
    public void testTemplateMetaData() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Timestamp timestamp = Timestamp.fromMillis(System.currentTimeMillis());

        TemplateMetaData meta = new TemplateMetaData();
        meta.setAutoUpdate(true)
                .setTemplateName("test")
                .setCurrentVersion(1)
                .setDescription("test template")
                .setLatestVersion(2)
                .setKeywordsToReplace("none")
                .setTimestamp(timestamp);

        assertTrue(meta.equals(meta));

        Result result = validator.validate(meta, "TemplateMetaData");
        assertTrue(result.valid);
        assertTrue(meta.getAutoUpdate());
        assertEquals((int) meta.getCurrentVersion(), 1);
        assertEquals(meta.getDescription(), "test template");
        assertEquals((int) meta.getLatestVersion(), 2);
        assertEquals(meta.getKeywordsToReplace(), "none");
        assertEquals(meta.getTemplateName(), "test");
        assertEquals(meta.getTimestamp(), timestamp);

        TemplateMetaData meta1 = new TemplateMetaData();
        meta1.setAutoUpdate(true)
                .setTemplateName("test")
                .setCurrentVersion(1)
                .setDescription("test template")
                .setLatestVersion(2)
                .setKeywordsToReplace("none")
                .setTimestamp(timestamp);

        assertTrue(meta.equals(meta1));
        assertFalse(meta.equals(null));
        assertFalse(meta.equals(3));

        meta1.setAutoUpdate(false);
        assertFalse(meta1.equals(meta));
        meta1.setAutoUpdate(null);
        assertFalse(meta1.equals(meta));
        meta1.setAutoUpdate(true);
        assertTrue(meta1.equals(meta));

        meta1.setCurrentVersion(2);
        assertFalse(meta1.equals(meta));
        meta1.setCurrentVersion(null);
        assertFalse(meta1.equals(meta));
        meta1.setCurrentVersion(1);
        assertTrue(meta1.equals(meta));

        meta1.setDescription("test test");
        assertFalse(meta1.equals(meta));
        meta1.setDescription(null);
        assertFalse(meta1.equals(meta));
        meta1.setDescription("test template");
        assertTrue(meta1.equals(meta));

        meta1.setLatestVersion(3);
        assertFalse(meta1.equals(meta));
        meta1.setLatestVersion(null);
        assertFalse(meta1.equals(meta));
        meta1.setLatestVersion(2);
        assertTrue(meta1.equals(meta));

        meta1.setKeywordsToReplace("service");
        assertFalse(meta1.equals(meta));
        meta1.setKeywordsToReplace(null);
        assertFalse(meta1.equals(meta));
        meta1.setKeywordsToReplace("none");
        assertTrue(meta1.equals(meta));

        meta1.setTimestamp(Timestamp.fromMillis(100));
        assertFalse(meta1.equals(meta));
        meta1.setTimestamp(null);
        assertFalse(meta1.equals(meta));
        meta1.setTimestamp(timestamp);
        assertTrue(meta1.equals(meta));

        meta1.setTemplateName("test2");
        assertFalse(meta1.equals(meta));
        meta1.setTemplateName(null);
        assertFalse(meta1.equals(meta));
        meta1.setTemplateName("test");
        assertTrue(meta1.equals(meta));
    }

    @Test
    public void testUserTokenMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        UserToken ut = new UserToken().setToken("testtoken").setHeader("hdr");

        Result result = validator.validate(ut, "UserToken");
        assertTrue(result.valid);

        assertEquals(ut.getToken(), "testtoken");
        assertEquals(ut.getHeader(), "hdr");

        UserToken ut2 = new UserToken().setToken("testtoken").setHeader("hdr");
        assertTrue(ut2.equals(ut));
        assertTrue(ut.equals(ut));

        ut2.setHeader(null);
        assertFalse(ut2.equals(ut));

        ut2.setToken(null);
        assertFalse(ut2.equals(ut));

        assertFalse(ut.equals(null));
        assertFalse(ut.equals(new String()));
    }

    @Test
    public void testEntityListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> elist = Arrays.asList("test.entity");

        EntityList el = new EntityList().setNames(elist);

        Result result = validator.validate(el, "EntityList");
        assertTrue(result.valid);

        assertEquals(el.getNames(), elist);

        EntityList el2 = new EntityList().setNames(elist);
        assertTrue(el2.equals(el));
        assertTrue(el.equals(el));

        el2.setNames(null);
        assertFalse(el2.equals(el));

        assertFalse(el.equals(null));
        assertFalse(el.equals(new String()));
    }

    @Test
    public void testPoliciesMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Assertion a = new Assertion().setRole("test.role.*").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);

        List<Policy> plist = Arrays.asList(new Policy().setName("test").setAssertions(Arrays.asList(a)).setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue")))));

        Policies ps1 = new Policies().setList(plist);

        Result result = validator.validate(ps1, "Policies");
        assertTrue(result.valid);

        assertEquals(ps1.getList(), plist);

        Policies ps2 = new Policies().setList(plist);
        assertTrue(ps2.equals(ps1));
        assertTrue(ps1.equals(ps1));

        ps2.setList(null);
        assertFalse(ps2.equals(ps1));

        assertFalse(ps1.equals(null));
        assertFalse(ps1.equals(new String()));
    }

    @Test
    public void testPoliciesMethodCaseSensitive() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Assertion a = new Assertion().setRole("test.role.*").setResource("test.ResourcE.*").setAction("Test-Action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);

        List<Policy> plist = Arrays.asList(new Policy().setName("test").setAssertions(Arrays.asList(a)).setCaseSensitive(true).setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue")))));

        Policies ps1 = new Policies().setList(plist);

        Result result = validator.validate(ps1, "Policies");
        assertTrue(result.valid);

        assertEquals(ps1.getList(), plist);

        Policies ps2 = new Policies().setList(plist);
        assertTrue(ps2.equals(ps1));
        assertTrue(ps1.equals(ps1));
        assertTrue(ps2.getList().get(0).getCaseSensitive());

        ps2.setList(null);
        assertFalse(ps2.equals(ps1));

        assertFalse(ps1.equals(null));
        assertFalse(ps1.equals(new String()));

        Policy policyCaseSensitiveCheck = new Policy().setName("test").setAssertions(Arrays.asList(a)).setCaseSensitive(null).setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertFalse(ps1.getList().get(0).equals(policyCaseSensitiveCheck));
        policyCaseSensitiveCheck.setCaseSensitive(false);
        assertFalse(ps1.getList().get(0).equals(policyCaseSensitiveCheck));
        policyCaseSensitiveCheck.setCaseSensitive(true);
        assertTrue(ps1.getList().get(0).equals(policyCaseSensitiveCheck));
    }

    @Test
    public void testTenancyMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> rg = Arrays.asList("test-resource");

        Tenancy t = new Tenancy().setDomain("test.domain").setService("test-service").setResourceGroups(rg);

        Result result = validator.validate(t, "Tenancy");
        assertTrue(result.valid);

        assertEquals(t.getDomain(), "test.domain");
        assertEquals(t.getService(), "test-service");
        assertEquals(t.getResourceGroups(), rg);
        assertTrue(t.getCreateAdminRole());

        Tenancy t2 = new Tenancy().setDomain("test.domain").setService("test-service").setResourceGroups(rg);
        assertNull(t2.getCreateAdminRole());
        t2.init();
        assertTrue(t2.getCreateAdminRole());

        assertTrue(t2.equals(t));
        assertTrue(t.equals(t));

        t2.setResourceGroups(null);
        assertFalse(t2.equals(t));
        t2.setResourceGroups(rg);
        t2.setService(null);
        assertFalse(t2.equals(t));
        t2.setService("test-service");
        t2.setDomain(null);
        assertFalse(t2.equals(t));
        t2.setDomain("test.domain");
        t2.setCreateAdminRole(null);
        assertFalse(t2.equals(t));
        t2.setCreateAdminRole(false);
        assertFalse(t2.equals(t));
        t2.setCreateAdminRole(true);
        assertFalse(t2.equals(null));
        assertFalse(t.equals(new String()));

        Tenancy t3 = new Tenancy().setCreateAdminRole(false);
        t3.init();
        assertFalse(t3.getCreateAdminRole());
    }

    @Test
    public void testResourceAccessListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Assertion a = new Assertion().setRole("test.role.*").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);

        List<Assertion> al = Arrays.asList(a);
        // ResourceAccess test
        ResourceAccess ra = new ResourceAccess().setPrincipal("test.principal").setAssertions(al);

        Result result = validator.validate(ra, "ResourceAccess");
        assertTrue(result.valid);

        assertEquals(ra.getPrincipal(), "test.principal");
        assertEquals(ra.getAssertions(), al);

        ResourceAccess ra2 = new ResourceAccess().setPrincipal("test.principal").setAssertions(al);
        assertTrue(ra2.equals(ra));
        assertTrue(ra.equals(ra));

        ra2.setAssertions(null);
        assertFalse(ra2.equals(ra));
        ra2.setPrincipal(null);
        assertFalse(ra2.equals(ra));
        assertFalse(ra.equals(new String()));

        // ResourceAccessList test
        List<ResourceAccess> ralist = Arrays.asList(ra);

        ResourceAccessList ral1 = new ResourceAccessList().setResources(ralist);
        assertTrue(ral1.equals(ral1));

        result = validator.validate(ral1, "ResourceAccessList");
        assertTrue(result.valid);

        assertEquals(ral1.getResources(), ralist);

        ResourceAccessList ral2 = new ResourceAccessList().setResources(ralist);
        assertTrue(ral2.equals(ral1));

        ral2.setResources(null);
        assertFalse(ral2.equals(ral1));

        assertFalse(ral1.equals(null));
        assertFalse(ral1.equals(new String()));
    }

    @Test
    public void testServicePrincipalMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        ServicePrincipal sp = new ServicePrincipal().setDomain("test.domain").setService("test-service")
                .setToken("test-token");

        Result result = validator.validate(sp, "ServicePrincipal");
        assertTrue(result.valid);

        assertEquals(sp.getDomain(), "test.domain");
        assertEquals(sp.getService(), "test-service");
        assertEquals(sp.getToken(), "test-token");

        ServicePrincipal sp2 = new ServicePrincipal().setDomain("test.domain").setService("test-service")
                .setToken("test-token");

        assertTrue(sp2.equals(sp));
        assertTrue(sp.equals(sp));

        sp2.setToken(null);
        assertFalse(sp2.equals(sp));
        sp2.setService(null);
        assertFalse(sp2.equals(sp));
        sp2.setDomain(null);
        assertFalse(sp2.equals(sp));
        assertFalse(sp2.equals(null));
        assertFalse(sp.equals(new String()));
    }

    @Test
    public void testTemplateMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<Role> rl = Arrays.asList(new Role().setName("sys.auth:role.admin").setMembers(Arrays.asList("user.test")));
        Assertion a = new Assertion().setRole("test.role").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);
        List<Assertion> assertions = new ArrayList<>();
        assertions.add(a);
        List<Policy> pl = Arrays.asList(new Policy().setName("sys.auth:policy.test-policy")
                .setAssertions(assertions).setModified(Timestamp.fromMillis(123456789123L)));

        TemplateMetaData meta = new TemplateMetaData();

        List<ServiceIdentity> sl = new ArrayList<>();
        Template t = new Template().setRoles(rl).setPolicies(pl).setServices(sl)
                .setMetadata(meta);

        Result result = validator.validate(t, "Template");
        assertTrue(result.valid, result.error);

        assertEquals(t.getPolicies(), pl);
        assertEquals(t.getRoles(), rl);
        assertEquals(t.getServices(), sl);
        assertEquals(t.getMetadata(), meta);

        Template t2 = new Template().setRoles(rl).setPolicies(pl).setServices(sl).setMetadata(meta);
        assertTrue(t2.equals(t));
        assertTrue(t.equals(t));

        t2.setServices(null);
        assertFalse(t2.equals(t));
        t2.setServices(sl);
        t2.setPolicies(null);
        assertFalse(t2.equals(t));
        t2.setPolicies(pl);
        t2.setRoles(null);
        assertFalse(t2.equals(t));
        t2.setRoles(rl);
        t2.setMetadata(null);
        assertFalse(t2.equals(t));
        t2.setMetadata(meta);

        assertFalse(t2.equals(null));
        assertFalse(t.equals(new String()));

        //test for service
        List<ServiceIdentity> services = Arrays.asList(new ServiceIdentity().setName("test.service")
                .setDescription("Test Description"));
        Template t3 = new Template().setRoles(rl).setPolicies(pl).setServices(services);

        Result result3 = validator.validate(t3, "Template");
        assertTrue(result3.valid, result3.error);
        assertEquals(t3.getServices(), services);
    }

    @Test
    public void testProviderResourceGroupRolesMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        TenantRoleAction tra = new TenantRoleAction().setRole("testrole").setAction("add");
        List<TenantRoleAction> tral = Arrays.asList(tra);

        ProviderResourceGroupRoles prgr = new ProviderResourceGroupRoles().setDomain("test.domain")
                .setService("test-service").setTenant("test.tenant").setRoles(tral).setResourceGroup("test-group");

        Result result = validator.validate(prgr, "ProviderResourceGroupRoles");
        assertTrue(result.valid);

        assertEquals(prgr.getDomain(), "test.domain");
        assertEquals(prgr.getService(), "test-service");
        assertEquals(prgr.getTenant(), "test.tenant");
        assertEquals(prgr.getRoles(), tral);
        assertEquals(prgr.getResourceGroup(), "test-group");

        ProviderResourceGroupRoles prgr2 = new ProviderResourceGroupRoles().setDomain("test.domain")
                .setService("test-service").setTenant("test.tenant").setRoles(tral).setResourceGroup("test-group");

        assertNull(prgr2.getCreateAdminRole());
        prgr2.init();
        assertTrue(prgr2.getCreateAdminRole());
        assertFalse(prgr2.getSkipPrincipalMember());

        assertTrue(prgr2.equals(prgr));
        assertTrue(prgr.equals(prgr));

        prgr2.setResourceGroup(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setResourceGroup("test-group");

        prgr2.setRoles(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setRoles(tral);

        prgr2.setTenant(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setTenant("test.tenant");

        prgr2.setService(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setService("test-service");

        prgr2.setDomain(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setDomain("test.domain");

        prgr2.setCreateAdminRole(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setCreateAdminRole(false);
        assertFalse(prgr2.equals(prgr));
        prgr2.setCreateAdminRole(true);
        assertTrue(prgr2.equals(prgr));

        prgr2.setSkipPrincipalMember(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setSkipPrincipalMember(true);
        assertFalse(prgr2.equals(prgr));
        prgr2.setSkipPrincipalMember(false);
        assertTrue(prgr2.equals(prgr));

        assertFalse(prgr2.equals(null));
        assertFalse(prgr.equals(new String()));

        // TenantResourceGroupRoles test
        TenantResourceGroupRoles trgr = new TenantResourceGroupRoles().setDomain("test.domain")
                .setService("test-service").setTenant("test.domain").setRoles(tral).setResourceGroup("test.tenant");
        result = validator.validate(trgr, "TenantResourceGroupRoles");
        assertTrue(result.valid);

        assertEquals(trgr.getDomain(), "test.domain");
        assertEquals(trgr.getService(), "test-service");
        assertEquals(trgr.getTenant(), "test.domain");
        assertEquals(trgr.getRoles(), tral);
        assertEquals(trgr.getResourceGroup(), "test.tenant");

        TenantResourceGroupRoles trgr2 = new TenantResourceGroupRoles().setDomain("test.domain")
                .setService("test-service").setTenant("test.domain").setRoles(tral).setResourceGroup("test.tenant");

        assertTrue(trgr.equals(trgr));
        assertTrue(trgr2.equals(trgr));

        trgr2.setResourceGroup(null);
        assertFalse(trgr2.equals(trgr));
        trgr2.setRoles(null);
        assertFalse(trgr2.equals(trgr));
        trgr2.setTenant(null);
        assertFalse(trgr2.equals(trgr));
        trgr2.setService(null);
        assertFalse(trgr2.equals(trgr));
        trgr2.setDomain(null);
        assertFalse(trgr2.equals(trgr));
        assertFalse(trgr.equals(new String()));

        ProviderResourceGroupRoles prgr3 = new ProviderResourceGroupRoles().setCreateAdminRole(false);
        prgr3.init();
        assertFalse(prgr3.getCreateAdminRole());
    }

    @Test
    public void testMemberNames() {
        String[] goodMemberNames = {
                "user.joe",
                "user.*",
                "athenz.storage.*",
                "athenz.storage.test-test",
                "user.3sets",
                "athenz.great-service",
                "athenz.great-service*",
                "test.joe*",
                "*"
        };

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        for (String s : goodMemberNames) {
            Result result = validator.validate(s, "MemberName");
            assertTrue(result.valid, s);
        }

        String[] badMemberNames = {
                "user.*joe",
                "*test",
                "user.joe*test",
                "test.joe**"
        };

        for (String s : badMemberNames) {
            Result result = validator.validate(s, "MemberName");
            assertFalse(result.valid, s);
        }
    }

    @Test
    public void testUserMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        User user1 = new User().setName("joe");
        assertTrue(user1.equals(user1));

        Result result = validator.validate(user1, "User");
        assertTrue(result.valid);
        assertEquals(user1.getName(), "joe");

        User user2 = new User().setName("test.joe");
        result = validator.validate(user2, "User");
        assertFalse(result.valid);

        User user3 = new User().setName("joe");
        User user4 = new User();

        assertTrue(user3.equals(user1));

        assertFalse(user2.equals(user1));
        assertFalse(user4.equals(user1));
        assertFalse(user1.equals(null));
    }

    @Test
    public void testUserListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        ArrayList<String> users1 = new ArrayList<>();
        users1.add("joe");
        users1.add("jane");

        UserList userList1 = new UserList().setNames(users1);
        assertTrue(userList1.equals(userList1));

        Result result = validator.validate(userList1, "UserList");
        assertTrue(result.valid);
        assertEquals(userList1.getNames().size(), 2);

        ArrayList<String> users2 = new ArrayList<>();
        users2.add("test.joe");
        UserList userList2 = new UserList().setNames(users2);
        result = validator.validate(userList2, "UserList");
        assertFalse(result.valid);

        UserList userList3 = new UserList().setNames(users1);
        assertTrue(userList3.equals(userList1));
        userList3.setNames(null);
        assertFalse(userList3.equals(userList1));

        assertFalse(userList2.equals(userList1));
        assertFalse(userList1.equals(null));
    }

    @Test
    public void testQuotaObject() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Quota quota = new Quota().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18)
                .setGroup(19).setGroupMember(20)
                .setModified(Timestamp.fromMillis(100));

        Result result = validator.validate(quota, "Quota");
        assertTrue(result.valid);

        assertEquals(quota.getName(), "athenz");
        assertEquals(quota.getAssertion(), 10);
        assertEquals(quota.getEntity(), 11);
        assertEquals(quota.getPolicy(), 12);
        assertEquals(quota.getPublicKey(), 13);
        assertEquals(quota.getRole(), 14);
        assertEquals(quota.getRoleMember(), 15);
        assertEquals(quota.getService(), 16);
        assertEquals(quota.getServiceHost(), 17);
        assertEquals(quota.getSubdomain(), 18);
        assertEquals(quota.getGroup(), 19);
        assertEquals(quota.getGroupMember(), 20);
        assertEquals(Timestamp.fromMillis(100), quota.getModified());

        Quota quota2 = new Quota().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18)
                .setGroup(19).setGroupMember(20)
                .setModified(Timestamp.fromMillis(100));

        assertTrue(quota2.equals(quota));
        assertTrue(quota.equals(quota));

        quota2.setModified(null);
        assertFalse(quota2.equals(quota));
        quota2.setModified(Timestamp.fromMillis(100));
        assertTrue(quota2.equals(quota));

        quota2.setPublicKey(101);
        assertFalse(quota2.equals(quota));
        quota2.setPublicKey(13);
        assertTrue(quota2.equals(quota));

        quota2.setServiceHost(101);
        assertFalse(quota2.equals(quota));
        quota2.setServiceHost(17);
        assertTrue(quota2.equals(quota));

        quota2.setService(103);
        assertFalse(quota2.equals(quota));
        quota2.setService(16);
        assertTrue(quota2.equals(quota));

        quota2.setEntity(103);
        assertFalse(quota2.equals(quota));
        quota2.setEntity(11);
        assertTrue(quota2.equals(quota));

        quota2.setAssertion(103);
        assertFalse(quota2.equals(quota));
        quota2.setAssertion(10);
        assertTrue(quota2.equals(quota));

        quota2.setPolicy(101);
        assertFalse(quota2.equals(quota));
        quota2.setPolicy(12);
        assertTrue(quota2.equals(quota));

        quota2.setRoleMember(103);
        assertFalse(quota2.equals(quota));
        quota2.setRoleMember(15);
        assertTrue(quota2.equals(quota));

        quota2.setRole(102);
        assertFalse(quota2.equals(quota));
        quota2.setRole(14);
        assertTrue(quota2.equals(quota));

        quota2.setSubdomain(102);
        assertFalse(quota2.equals(quota));
        quota2.setSubdomain(18);
        assertTrue(quota2.equals(quota));

        quota2.setGroup(102);
        assertFalse(quota2.equals(quota));
        quota2.setGroup(19);
        assertTrue(quota2.equals(quota));

        quota2.setGroupMember(102);
        assertFalse(quota2.equals(quota));
        quota2.setGroupMember(20);
        assertTrue(quota2.equals(quota));

        quota2.setName(null);
        assertFalse(quota2.equals(quota));
        quota2.setName("name2");
        assertFalse(quota2.equals(quota));

        assertFalse(quota2.equals(null));
        assertFalse(quota2.equals(new String()));
    }

    @Test
    public void testDomainRoleMember() {

        List<MemberRole> list1 = new ArrayList<>();
        list1.add(new MemberRole().setRoleName("role1"));

        List<MemberRole> list2 = new ArrayList<>();

        DomainRoleMember mbr1 = new DomainRoleMember();
        mbr1.setMemberName("mbr1");
        mbr1.setMemberRoles(list1);

        assertEquals("mbr1", mbr1.getMemberName());
        assertEquals(list1, mbr1.getMemberRoles());

        assertTrue(mbr1.equals(mbr1));
        assertFalse(mbr1.equals(null));

        DomainRoleMember mbr2 = new DomainRoleMember();
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMemberName("mbr2");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMemberName("mbr1");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMemberRoles(list2);
        assertFalse(mbr2.equals(mbr1));

        list2.add(new MemberRole().setRoleName("role1"));
        assertTrue(mbr2.equals(mbr1));

        MemberRole mbr3 = new MemberRole();
        mbr3.init();
        assertTrue(mbr3.getActive());

        mbr3.setActive(false);
        mbr3.init();
        assertFalse(mbr3.getActive());
    }

    @Test
    public void testDomainRoleMembers() {

        List<DomainRoleMember> list1 = new ArrayList<>();
        list1.add(new DomainRoleMember().setMemberName("mbr1"));

        List<DomainRoleMember> list2 = new ArrayList<>();

        DomainRoleMembers mbr1 = new DomainRoleMembers();
        mbr1.setDomainName("dom1");
        mbr1.setMembers(list1);

        assertEquals("dom1", mbr1.getDomainName());
        assertEquals(list1, mbr1.getMembers());

        assertTrue(mbr1.equals(mbr1));
        assertFalse(mbr1.equals(null));

        DomainRoleMembers mbr2 = new DomainRoleMembers();
        assertFalse(mbr2.equals(mbr1));

        mbr2.setDomainName("dom2");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setDomainName("dom1");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMembers(list2);
        assertFalse(mbr2.equals(mbr1));

        list2.add(new DomainRoleMember().setMemberName("mbr1"));
        assertTrue(mbr2.equals(mbr1));
    }

    @Test
    public void testDomainTemplateMethod() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> dl = Arrays.asList("user_provisioning");

        DomainTemplate dt = new DomainTemplate().setTemplateNames(dl);
        Result result = validator.validate(dt, "DomainTemplate");
        assertTrue(result.valid);

        List<TemplateParam> params1 = new ArrayList<>();
        params1.add(new TemplateParam().setName("name1").setValue("val1"));

        List<TemplateParam> params2 = new ArrayList<>();

        List<String> names1 = new ArrayList<>();
        names1.add("tmpl1");

        List<String> names2 = new ArrayList<>();

        DomainTemplate dt1 = new DomainTemplate();
        dt1.setParams(params1);
        dt1.setTemplateNames(names1);

        assertEquals(params1, dt1.getParams());
        assertEquals(names1, dt1.getTemplateNames());

        assertTrue(dt1.equals(dt1));
        assertFalse(dt1.equals(null));
        assertFalse(dt1.equals(new String()));

        DomainTemplate dt2 = new DomainTemplate();
        assertFalse(dt2.equals(dt1));

        dt2.setTemplateNames(names2);
        assertFalse(dt2.equals(dt1));

        names2.add("tmpl1");
        assertFalse(dt2.equals(dt1));

        dt2.setParams(params2);
        assertFalse(dt2.equals(dt1));

        params2.add(new TemplateParam().setName("name1").setValue("val1"));
        assertTrue(dt2.equals(dt1));
    }

    @Test
    public void testTenantRoleAction() {

        TenantRoleAction tra1 = new TenantRoleAction();
        tra1.setAction("action1");
        tra1.setRole("role1");

        assertEquals(tra1, tra1);
        assertEquals("role1", tra1.getRole());
        assertEquals("action1", tra1.getAction());

        assertFalse(tra1.equals(null));
        assertFalse(tra1.equals(new String()));

        TenantRoleAction tra2 = new TenantRoleAction();
        tra2.setAction("action1");
        tra2.setRole("role1");

        assertTrue(tra2.equals(tra1));

        tra2.setAction("action2");
        assertFalse(tra2.equals(tra1));

        tra2.setAction(null);
        assertFalse(tra2.equals(tra1));

        tra2.setRole("role2");
        assertFalse(tra2.equals(tra1));

        tra2.setRole(null);
        assertFalse(tra2.equals(tra1));
    }

    @Test
    public void testRoleSystemMetaMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        RoleSystemMeta rsm = new RoleSystemMeta();

        Result result = validator.validate(rsm, "RoleSystemMeta");
        assertTrue(result.valid);

        assertFalse(rsm.getAuditEnabled());

        RoleSystemMeta rsm2 = new RoleSystemMeta();
        assertFalse(rsm2.equals(rsm));
        rsm2.setAuditEnabled(false);
        assertTrue(rsm2.equals(rsm));
        assertTrue(rsm.equals(rsm));

        rsm2.setAuditEnabled(null);
        assertFalse(rsm2.equals(rsm));

        assertFalse(rsm2.equals(null));
        assertFalse(rsm.equals(new String()));
    }

    @Test
    public void testDomainRoleMembership() {

        DomainRoleMembership drm = new DomainRoleMembership();
        List<DomainRoleMembers> domainRoleMembersList = new ArrayList<>();
        List<DomainRoleMember> list = new ArrayList<>();
        list.add(new DomainRoleMember().setMemberName("mbr"));
        DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
        domainRoleMembers.setDomainName("testdom");
        domainRoleMembers.setMembers(list);
        domainRoleMembersList.add(domainRoleMembers);

        drm.setDomainRoleMembersList(domainRoleMembersList);

        assertNotNull(drm.getDomainRoleMembersList());

        DomainRoleMembership drm1 = new DomainRoleMembership();
        List<DomainRoleMembers> domainRoleMembersList1 = new ArrayList<>();
        List<DomainRoleMember> list1 = new ArrayList<>();
        list1.add(new DomainRoleMember().setMemberName("mbr1"));
        DomainRoleMembers domainRoleMembers1 = new DomainRoleMembers();
        domainRoleMembers1.setDomainName("testdom1");
        domainRoleMembers1.setMembers(list1);
        domainRoleMembersList1.add(domainRoleMembers1);

        drm1.setDomainRoleMembersList(domainRoleMembersList1);

        assertFalse(drm.equals(drm1));

        DomainRoleMembership drm2 = new DomainRoleMembership();
        List<DomainRoleMembers> domainRoleMembersList2 = new ArrayList<>();
        List<DomainRoleMember> list2 = new ArrayList<>();
        list2.add(new DomainRoleMember().setMemberName("mbr"));
        DomainRoleMembers domainRoleMembers2 = new DomainRoleMembers();
        domainRoleMembers2.setDomainName("testdom");
        domainRoleMembers2.setMembers(list2);
        domainRoleMembersList2.add(domainRoleMembers2);

        drm2.setDomainRoleMembersList(domainRoleMembersList2);
        assertTrue(drm.equals(drm2));
        assertTrue(drm.equals(drm));

        drm2.setDomainRoleMembersList(null);
        assertFalse(drm2.equals(drm));
        assertFalse(drm2.equals(null));
    }

    @Test
    public void testServiceIdentitySystemMetaMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta().setProviderEndpoint("https://host:443/endpoint");
        assertTrue(meta.equals(meta));

        Result result = validator.validate(meta, "ServiceIdentitySystemMeta");
        assertTrue(result.valid);

        assertEquals(meta.getProviderEndpoint(), "https://host:443/endpoint");

        ServiceIdentitySystemMeta meta2 = new ServiceIdentitySystemMeta().setProviderEndpoint("https://host:443/endpoint");
        assertTrue(meta2.equals(meta));

        meta2.setProviderEndpoint("https://host:443/endpoint2");
        assertFalse(meta2.equals(meta));
        meta2.setProviderEndpoint(null);
        assertFalse(meta2.equals(meta));
        meta2.setProviderEndpoint("https://host:443/endpoint2");

        assertFalse(meta2.equals(null));

        assertFalse(meta.equals(new String()));
    }

    @Test
    public void testJWSDomain() {

        Map<String, String> headers = new HashMap<>();
        JWSDomain jws1 = new JWSDomain()
                .setHeader(headers)
                .setPayload("payload")
                .setProtectedHeader("protectedHeader")
                .setSignature("signature");

        assertEquals(jws1.getHeader(), headers);
        assertEquals(jws1.getPayload(), "payload");
        assertEquals(jws1.getProtectedHeader(), "protectedHeader");
        assertEquals(jws1.getSignature(), "signature");

        JWSDomain jws2 = new JWSDomain()
                .setHeader(headers)
                .setPayload("payload")
                .setProtectedHeader("protectedHeader")
                .setSignature("signature");
        assertTrue(jws2.equals(jws1));
        assertTrue(jws2.equals(jws2));
        assertFalse(jws2.equals(null));

        jws2.setPayload("newpayload");
        assertFalse(jws2.equals(jws1));
        jws2.setPayload(null);
        assertFalse(jws2.equals(jws1));
        jws2.setPayload("payload");
        assertTrue(jws2.equals(jws1));

        jws2.setProtectedHeader("newprotectedHeader");
        assertFalse(jws2.equals(jws1));
        jws2.setProtectedHeader(null);
        assertFalse(jws2.equals(jws1));
        jws2.setProtectedHeader("protectedHeader");
        assertTrue(jws2.equals(jws1));

        jws2.setSignature("newsignature");
        assertFalse(jws2.equals(jws1));
        jws2.setSignature(null);
        assertFalse(jws2.equals(jws1));
        jws2.setSignature("signature");
        assertTrue(jws2.equals(jws1));

        Map<String, String> headers2 = new HashMap<>();
        headers2.put("key", "value");
        jws2.setHeader(headers2);
        assertFalse(jws2.equals(jws1));
        jws2.setHeader(null);
        assertFalse(jws2.equals(jws1));
        jws2.setHeader(headers);
        assertTrue(jws2.equals(jws1));
    }

    @Test
    public void testDomainTemplateDetailsList() {
        ZMSSchema schema1 = new ZMSSchema();
        assertNotNull(schema1);
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        TemplateMetaData meta = new TemplateMetaData();
        List<TemplateMetaData> templateList = new ArrayList<>();
        meta.setCurrentVersion(1);
        templateList.add(meta);

        DomainTemplateDetailsList tl = new DomainTemplateDetailsList().setMetaData(templateList);


        Result result = validator.validate(tl, "DomainTemplateDetailsList");
        assertTrue(result.valid);
        assertEquals(tl.getMetaData(), templateList);


        DomainTemplateDetailsList tl2 = new DomainTemplateDetailsList().setMetaData(templateList);
        assertTrue(tl2.equals(tl));
        assertTrue(tl.equals(tl));

        DomainTemplateDetailsList tl3 = new DomainTemplateDetailsList();
        assertFalse(tl2.equals(tl3));

        DomainTemplateDetailsList tl4 = null;
        assertFalse(tl2.equals(tl4));

        tl2.setMetaData(null);
        assertFalse(tl2.equals(tl));
        assertFalse(tl.equals(null));
    }

    @Test
    public void testTagValueList() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> strList = Collections.singletonList("member");

        TagValueList stl = new TagValueList().setList(strList);

        Result result = validator.validate(stl, "TagValueList");
        assertTrue(result.valid);
        assertEquals(strList, stl.getList());

        TagValueList stl2 = new TagValueList().setList(strList);
        assertEquals(stl2, stl);
        assertEquals(stl, stl);

        stl2.setList(null);
        assertNotEquals(stl, stl2);

        assertNotEquals(stl2, stl);

        stl2.setList(Collections.singletonList("member2"));
        assertNotEquals(stl2, stl);
        assertNotEquals(stl, stl2);
        assertNotEquals(stl, null);
        assertFalse(stl.equals("str"));

        TagValueList tvl = new TagValueList().setList(Collections.singletonList("/homes"));
        Result resultTvl = validator.validate(tvl, "TagValueList");
        assertTrue(resultTvl.valid);

        tvl = new TagValueList().setList(Collections.singletonList("/homes/"));
        resultTvl = validator.validate(tvl, "TagValueList");
        assertTrue(resultTvl.valid);

        tvl = new TagValueList().setList(Collections.singletonList("/homes/home"));
        resultTvl = validator.validate(tvl, "TagValueList");
        assertTrue(resultTvl.valid);

        tvl = new TagValueList().setList(Collections.singletonList("/homes/home/"));
        resultTvl = validator.validate(tvl, "TagValueList");
        assertTrue(resultTvl.valid);
    }

    private UserAuthorityAttributeMap getUserAuthorityAttributeMapForTest() {
        List<String> boolValues = new ArrayList<>();
        boolValues.add("boolValue1");
        boolValues.add("boolValue2");

        List<String> dateValues = new ArrayList<>();
        dateValues.add("dateValue1");
        dateValues.add("dateValue2");

        UserAuthorityAttributes userAuthorityBoolAttributes = new UserAuthorityAttributes();
        userAuthorityBoolAttributes.setValues(boolValues);
        UserAuthorityAttributes userAuthorityDateAttributes = new UserAuthorityAttributes();
        userAuthorityDateAttributes.setValues(dateValues);
        Map<String, UserAuthorityAttributes> attributes = new HashMap<>();
        attributes.put("bool", userAuthorityBoolAttributes);
        attributes.put("date", userAuthorityDateAttributes);

        UserAuthorityAttributeMap userAuthorityAttributeMap = new UserAuthorityAttributeMap();
        userAuthorityAttributeMap.setAttributes(attributes);
        return userAuthorityAttributeMap;
    }

    @Test
    public void testUserAuthorityValuesList() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        UserAuthorityAttributeMap userAuthorityAttributeMap = getUserAuthorityAttributeMapForTest();
        Result result = validator.validate(userAuthorityAttributeMap, "UserAuthorityAttributeMap");
        assertTrue(result.valid);
        assertEquals(userAuthorityAttributeMap.getAttributes().get("bool").getValues().get(0), "boolValue1");
        assertEquals(userAuthorityAttributeMap.getAttributes().get("bool").getValues().get(1), "boolValue2");
        assertEquals(userAuthorityAttributeMap.getAttributes().get("date").getValues().get(0), "dateValue1");
        assertEquals(userAuthorityAttributeMap.getAttributes().get("date").getValues().get(1), "dateValue2");

        UserAuthorityAttributeMap userAuthorityAttributeMap2 = getUserAuthorityAttributeMapForTest();
        assertEquals(userAuthorityAttributeMap, userAuthorityAttributeMap2);

        userAuthorityAttributeMap2.getAttributes().get("bool").getValues().remove("boolValue1");
        assertFalse(userAuthorityAttributeMap.equals(userAuthorityAttributeMap2));
        userAuthorityAttributeMap.getAttributes().get("bool").getValues().remove("boolValue1");
        assertTrue(userAuthorityAttributeMap.equals(userAuthorityAttributeMap2));
        assertFalse(userAuthorityAttributeMap.equals(null));
        assertFalse(userAuthorityAttributeMap.equals(new Object()));
        assertFalse(userAuthorityAttributeMap.equals(new UserAuthorityAttributeMap()));
        assertFalse(userAuthorityAttributeMap.equals(new UserAuthorityAttributeMap().setAttributes(new HashMap<>())));

        userAuthorityAttributeMap2.getAttributes().put("newType", new UserAuthorityAttributes());
        assertFalse(userAuthorityAttributeMap.equals(userAuthorityAttributeMap2));
        userAuthorityAttributeMap.getAttributes().put("newType", new UserAuthorityAttributes());
        assertTrue(userAuthorityAttributeMap.equals(userAuthorityAttributeMap2));

        userAuthorityAttributeMap2.getAttributes().remove("date");
        assertFalse(userAuthorityAttributeMap.equals(userAuthorityAttributeMap2));
        userAuthorityAttributeMap.getAttributes().remove("date");
        assertTrue(userAuthorityAttributeMap.equals(userAuthorityAttributeMap2));

        UserAuthorityAttributes userAuthoritylAttributes = new UserAuthorityAttributes();
        assertFalse(userAuthoritylAttributes.equals(null));
        UserAuthorityAttributes userAuthoritylAttributes2 = new UserAuthorityAttributes();
        assertTrue(userAuthoritylAttributes.equals(userAuthoritylAttributes2));
        userAuthoritylAttributes.setValues(new ArrayList<>());
        assertFalse(userAuthoritylAttributes.equals(userAuthoritylAttributes2));
        userAuthoritylAttributes2.setValues(new ArrayList<>());
        assertTrue(userAuthoritylAttributes.equals(userAuthoritylAttributes2));
    }

    @Test
    public void testDependentService() {

        DependentService a = new DependentService().setService("testService");
        assertEquals(a.getService(), "testService");
        assertTrue(a.equals(a));

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(a, "DependentService");
        assertTrue(result.valid);

        assertFalse(a.equals(null));

        DependentService a2 = new DependentService();
        assertFalse(a2.equals(a));
        a2.setService("testService2");
        assertFalse(a2.equals(a));
        a2.setService("testService");
        assertTrue(a2.equals(a));

        assertFalse(a.equals(new String()));
    }

    @Test
    public void testDependentServiceResourceGroup() {

        List<String> resourceGroups = Arrays.asList("group1", "group2");

        DependentServiceResourceGroup a = new DependentServiceResourceGroup().setService("testService").setDomain("testTenantDomain").setResourceGroups(resourceGroups);
        assertEquals(a.getService(), "testService");
        assertEquals(a.getDomain(), "testTenantDomain");
        assertEquals(a.getResourceGroups(), resourceGroups);

        assertTrue(a.equals(a));

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(a, "DependentServiceResourceGroup");
        assertTrue(result.valid);

        assertFalse(a.equals(null));

        DependentServiceResourceGroup a2 = new DependentServiceResourceGroup();
        assertFalse(a2.equals(a));
        a2.setService("testService2");
        assertFalse(a2.equals(a));
        a2.setService("testService");
        assertFalse(a2.equals(a));
        a2.setDomain("testTenantDomain");
        assertFalse(a2.equals(a));
        a2.setResourceGroups(resourceGroups);
        assertTrue(a2.equals(a));

        assertFalse(a.equals(new DependentServiceResourceGroup()));
    }

    @Test
    public void testDependentServiceResourceGroupList() {

        DependentServiceResourceGroup dependentServiceResourceGroup1 = new DependentServiceResourceGroup().setService("service1").setDomain("testTenantDomain").setResourceGroups(Arrays.asList("rsg1", "rsg2"));
        DependentServiceResourceGroup dependentServiceResourceGroup2 = new DependentServiceResourceGroup().setService("service2").setDomain("testTenantDomain").setResourceGroups(Arrays.asList("rsg3", "rsg4"));
        DependentServiceResourceGroup dependentServiceResourceGroup3 = new DependentServiceResourceGroup().setService("service3").setDomain("testTenantDomain");
        List<DependentServiceResourceGroup> serviceAndResourceGroups = Arrays.asList(
                dependentServiceResourceGroup1,
                dependentServiceResourceGroup2,
                dependentServiceResourceGroup3
        );

        DependentServiceResourceGroupList a = new DependentServiceResourceGroupList().setServiceAndResourceGroups(serviceAndResourceGroups);
        assertEquals(a.getServiceAndResourceGroups(), serviceAndResourceGroups);

        assertTrue(a.equals(a));

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(a, "DependentServiceResourceGroupList");
        assertTrue(result.valid);

        assertFalse(a.equals(null));

        DependentServiceResourceGroupList a2 = new DependentServiceResourceGroupList();
        assertFalse(a2.equals(a));
        a2.setServiceAndResourceGroups(new ArrayList<>());
        assertFalse(a2.equals(a));
        a2.setServiceAndResourceGroups(Arrays.asList(
                dependentServiceResourceGroup1,
                dependentServiceResourceGroup2
        ));
        assertFalse(a2.equals(a));
        a2.setServiceAndResourceGroups(Arrays.asList(
                dependentServiceResourceGroup1,
                dependentServiceResourceGroup2,
                dependentServiceResourceGroup3
        ));
        assertTrue(a2.equals(a));

        assertFalse(a.equals(new DependentServiceResourceGroupList()));
    }

    @Test
    public void testAuthHistoryDependencies() {
        AuthHistoryDependencies a = new AuthHistoryDependencies();
        AuthHistoryDependencies a2 = new AuthHistoryDependencies();
        assertEquals(a, a2);
        assertFalse(a.equals(null));
        assertFalse(a.equals(new Object()));

        a.setIncomingDependencies(new ArrayList<>());
        assertNotEquals(a, a2);
        a2.setIncomingDependencies(new ArrayList<>());
        assertEquals(a, a2);

        a.setOutgoingDependencies(new ArrayList<>());
        assertNotEquals(a, a2);
        a2.setOutgoingDependencies(new ArrayList<>());
        assertEquals(a, a2);

        AuthHistory authHistory = new AuthHistory();
        assertFalse(authHistory.equals(null));
        assertFalse(authHistory.equals(new Object()));

        a.setIncomingDependencies(Arrays.asList(authHistory));
        assertNotEquals(a, a2);
        AuthHistory authHistory2 = new AuthHistory();
        a2.setIncomingDependencies(Arrays.asList(authHistory2));
        assertEquals(a, a2);
        a.getIncomingDependencies().equals(a2.getIncomingDependencies());

        a.setOutgoingDependencies(Arrays.asList(authHistory));
        assertNotEquals(a, a2);
        a2.setOutgoingDependencies(Arrays.asList(authHistory2));
        assertEquals(a, a2);
        a.getOutgoingDependencies().equals(a2.getOutgoingDependencies());

        authHistory.setUriDomain("test");
        assertNotEquals(a, a2);
        authHistory2.setUriDomain("test");
        assertEquals(a, a2);
        authHistory.getUriDomain().equals(authHistory2.getUriDomain());

        authHistory.setPrincipalDomain("test2");
        assertNotEquals(a, a2);
        authHistory2.setPrincipalDomain("test2");
        assertEquals(a, a2);
        authHistory.getPrincipalDomain().equals(authHistory2.getPrincipalDomain());

        authHistory.setPrincipalName("principal");
        assertNotEquals(a, a2);
        authHistory2.setPrincipalName("principal");
        assertEquals(a, a2);
        authHistory.getPrincipalName().equals(authHistory2.getPrincipalName());

        authHistory.setEndpoint("https://some.endpoint");
        assertNotEquals(a, a2);
        authHistory2.setEndpoint("https://some.endpoint");
        assertEquals(a, a2);
        authHistory.getEndpoint().equals(authHistory2.getEndpoint());

        Timestamp timestamp = Timestamp.fromCurrentTime();
        authHistory.setTimestamp(timestamp);
        assertNotEquals(a, a2);
        authHistory2.setTimestamp(timestamp);
        assertEquals(a, a2);
        authHistory.getTimestamp().equals(authHistory2.getTimestamp());

        authHistory.setTtl(1655282257L);
        assertNotEquals(a, a2);
        authHistory2.setTtl(1655282257L);
        assertEquals(a, a2);
        assertEquals(authHistory.getTtl(), authHistory2.getTtl());
    }
}

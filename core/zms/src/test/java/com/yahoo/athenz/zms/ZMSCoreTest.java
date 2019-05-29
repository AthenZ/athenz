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

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

import static org.testng.Assert.*;
import org.testng.annotations.Test;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

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
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("user:doe"); // new
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
    public void testRolesMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        RoleAuditLog ral = new RoleAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");

        List<RoleAuditLog> rall = Arrays.asList(ral);

        // Role test
        List<String> members = Arrays.asList("user.boynton");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("member1"));

        Role r = new Role().setName("sys.auth:role.admin").setMembers(members).setRoleMembers(roleMembers)
                .setModified(Timestamp.fromMillis(123456789123L)).setTrust("domain.admin").setAuditLog(rall);
        Result result = validator.validate(r, "Role");
        assertTrue(result.valid);

        assertEquals(r.getName(), "sys.auth:role.admin");
        assertEquals(r.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(r.getMembers(), members);
        assertEquals(r.getTrust(), "domain.admin");
        assertEquals(r.getAuditLog(), rall);
        assertEquals(r.getRoleMembers(), roleMembers);

        Role r2 = new Role().setName("sys.auth:role.admin").setMembers(members).setRoleMembers(roleMembers)
                .setModified(Timestamp.fromMillis(123456789123L)).setTrust("domain.admin").setAuditLog(rall);
        assertTrue(r2.equals(r));
        assertTrue(r.equals(r));
        
        r2.setAuditLog(null);
        assertFalse(r2.equals(r));
        r2.setTrust(null);
        assertFalse(r2.equals(r));
        r2.setRoleMembers(null);
        assertFalse(r2.equals(r));
        r2.setMembers(null);
        assertFalse(r2.equals(r));
        r2.setModified(null);
        assertFalse(r2.equals(r));
        r2.setName(null);
        assertFalse(r2.equals(r));
        assertFalse(r.equals(new String()));

        List<Role> rl = Arrays.asList(r);

        // Roles test
        Roles rs1 = new Roles().setList(rl);
        assertTrue(rs1.equals(rs1));

        result = validator.validate(rs1, "Roles");
        assertTrue(result.valid);

        assertEquals(rs1.getList(), rl);

        Roles rs2 = new Roles().setList(rl);
        assertTrue(rs2.equals(rs1));

        rs2.setList(null);
        assertFalse(rs2.equals(rs1));

        assertFalse(rs1.equals(null));
        assertFalse(rs1.equals(new String()));
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
                .setAssertions(al);
        Result result = validator.validate(p, "Policy");
        assertTrue(result.valid);

        assertEquals(p.getName(), "test-policy");
        assertEquals(p.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(p.getAssertions(), al);

        Policy p2 = new Policy().setName("test-policy").setModified(Timestamp.fromMillis(123456789123L))
                .setAssertions(al);

        assertTrue(p2.equals(p));
        assertTrue(p.equals(p));

        p2.setAssertions(null);
        assertFalse(p2.equals(p));
        p2.setModified(null);
        assertFalse(p2.equals(p));
        p2.setName(null);
        assertFalse(p2.equals(p));
        assertFalse(p.equals(new String()));

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
                .setDescription("description");
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

        ServiceIdentity si2 = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test").setGroup("test.group")
                .setDescription("description");

        assertTrue(si2.equals(si));
        assertTrue(si.equals(si));
        
        si2.setGroup(null);
        assertFalse(si2.equals(si));
        si2.setUser(null);
        assertFalse(si2.equals(si));
        si2.setHosts(null);
        assertFalse(si2.equals(si));
        si2.setExecutable(null);
        assertFalse(si2.equals(si));
        si2.setModified(null);
        assertFalse(si2.equals(si));
        si2.setProviderEndpoint(null);
        assertFalse(si2.equals(si));
        si2.setPublicKeys(null);
        assertFalse(si2.equals(si));
        si2.setDescription(null);
        assertFalse(si2.equals(si));
        si2.setName(null);
        assertFalse(si2.equals(si));
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

        // DomainData test
        List<Entity> elist = new ArrayList<>();
        DomainData dd = new DomainData().setName("test.domain").setAccount("user.test").setYpmId(1).setRoles(rl)
                .setPolicies(sp).setServices(sil).setEntities(elist).setModified(Timestamp.fromMillis(123456789123L))
                .setEnabled(true).setApplicationId("101").setCertDnsDomain("athenz.cloud");
        result = validator.validate(dd, "DomainData");
        assertTrue(result.valid, result.error);

        assertEquals(dd.getName(), "test.domain");
        assertEquals(dd.getAccount(), "user.test");
        assertEquals((int) dd.getYpmId(), 1);
        assertEquals(dd.getRoles(), rl);
        assertEquals(dd.getPolicies(), sp);
        assertEquals(dd.getServices(), sil);
        assertEquals(dd.getEntities(), elist);
        assertEquals(dd.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals("101", dd.getApplicationId());
        assertTrue(dd.getEnabled());
        assertEquals(dd.getCertDnsDomain(), "athenz.cloud");

        DomainData dd2 = new DomainData().setName("test.domain").setAccount("user.test").setYpmId(1).setRoles(rl)
                .setPolicies(sp).setServices(sil).setEntities(elist).setModified(Timestamp.fromMillis(123456789123L))
                .setEnabled(true).setApplicationId("101").setCertDnsDomain("athenz.cloud");
        assertTrue(dd.equals(dd2));

        dd2.setCertDnsDomain(null);
        assertFalse(dd2.equals(dd));

        dd2.setApplicationId(null);
        assertFalse(dd2.equals(dd));

        dd2.setModified(null);
        assertFalse(dd2.equals(dd));
        
        dd2.setModified(Timestamp.fromMillis(123456789123L));
        dd2.setEntities(null);
        assertFalse(dd2.equals(dd));
        
        dd2.setEntities(elist);
        dd2.setServices(null);
        assertFalse(dd2.equals(dd));
        
        dd2.setServices(sil);
        dd2.setPolicies(null);
        assertFalse(dd2.equals(dd));
        
        dd2.setPolicies(sp);
        dd2.setRoles(null);
        assertFalse(dd2.equals(dd));
        
        dd2.setRoles(rl);
        dd2.setEnabled(false);
        assertFalse(dd2.equals(dd));
        dd2.setEnabled(null);
        assertFalse(dd2.equals(dd));

        dd2.setEnabled(true);
        dd2.setYpmId(null);
        assertFalse(dd2.equals(dd));

        dd2.setYpmId(1);
        dd2.setAccount(null);
        assertFalse(dd2.equals(dd));
        
        dd2.setAccount("user.test");
        dd2.setName(null);
        assertFalse(dd2.equals(dd));
        assertFalse(dd.equals(new String()));

        // SignedDomain test
        SignedDomain sd = new SignedDomain().setDomain(dd).setSignature("zmssignature").setKeyId("v1");
        result = validator.validate(sd, "SignedDomain");
        assertTrue(result.valid);

        assertEquals(sd.getDomain(), dd);
        assertEquals(sd.getSignature(), "zmssignature");
        assertEquals(sd.getKeyId(), "v1");

        SignedDomain sd2 = new SignedDomain().setDomain(dd).setSignature("zmssignature").setKeyId("v1");
        assertTrue(sd2.equals(sd));
        assertTrue(sd.equals(sd));
        
        sd2.setKeyId(null);
        assertFalse(sd2.equals(sd));
        sd2.setSignature(null);
        assertFalse(sd2.equals(sd));
        sd2.setDomain(null);
        assertFalse(sd2.equals(sd));
        assertFalse(sd.equals(new String()));

        List<SignedDomain> sdl = Arrays.asList(sd);

        // SignedDomains test
        SignedDomains sds1 = new SignedDomains().setDomains(sdl);
        result = validator.validate(sds1, "SignedDomains");
        assertTrue(result.valid);

        assertEquals(sds1.getDomains(), sdl);

        SignedDomains sds2 = new SignedDomains().setDomains(sdl);
        assertTrue(sds2.equals(sds1));
        assertTrue(sds1.equals(sds1));

        sds2.setDomains(null);
        assertFalse(sds2.equals(sds1));

        assertFalse(sds1.equals(null));
        assertFalse(sds1.equals(new String()));
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
    public void testDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Domain d = new Domain();
        d.setName("test.domain").setModified(Timestamp.fromMillis(123456789123L)).setId(UUID.fromMillis(100))
                .setDescription("test desc").setOrg("test-org").setEnabled(true).setAuditEnabled(true)
                .setAccount("user.test").setYpmId(1).setApplicationId("101").setCertDnsDomain("athenz.cloud");
        Result result = validator.validate(d, "Domain");
        assertTrue(result.valid);

        assertEquals(d.getName(), "test.domain");
        assertEquals(d.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(d.getId(), UUID.fromMillis(100));
        assertEquals(d.getDescription(), "test desc");
        assertEquals(d.getOrg(), "test-org");
        assertTrue(d.getEnabled());
        assertTrue(d.getAuditEnabled());
        assertEquals(d.getAccount(), "user.test");
        assertEquals((int) d.getYpmId(), 1);
        assertEquals(d.getApplicationId(), "101");
        assertEquals(d.getCertDnsDomain(), "athenz.cloud");

        Domain d2 = new Domain();
        d2.setName("test.domain").setModified(Timestamp.fromMillis(123456789123L)).setId(UUID.fromMillis(100))
                .setDescription("test desc").setOrg("test-org").setEnabled(true).setAuditEnabled(true)
                .setAccount("user.test").setYpmId(1).setApplicationId("101").setCertDnsDomain("athenz.cloud");

        assertTrue(d2.equals(d));
        assertTrue(d.equals(d));

        d2.setId(UUID.fromMillis(101));
        assertFalse(d2.equals(d));
        d2.setId(null);
        assertFalse(d2.equals(d));
        d2.setModified(null);
        assertFalse(d2.equals(d));
        d2.setName(null);
        assertFalse(d2.equals(d));
        d2.setCertDnsDomain(null);
        assertFalse(d2.equals(d));
        d2.setApplicationId(null);
        assertFalse(d2.equals(d));
        d2.setYpmId(null);
        assertFalse(d2.equals(d));
        d2.setAccount(null);
        assertFalse(d2.equals(d));
        d2.setAuditEnabled(null);
        assertFalse(d2.equals(d));
        d2.setEnabled(null);
        assertFalse(d2.equals(d));
        d2.setOrg(null);
        assertFalse(d2.equals(d));
        d2.setDescription(null);
        assertFalse(d2.equals(d));
        assertFalse(d2.equals(null));
        assertFalse(d.equals(new String()));
    }

    @Test
    public void testDomainList() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> domainnames = Arrays.asList("test.domain");

        DomainList dl = new DomainList().setNames(domainnames).setNext("next");

        Result result = validator.validate(dl, "DomainList");
        assertTrue(result.valid);

        assertEquals(dl.getNames(), domainnames);
        assertEquals(dl.getNext(), "next");

        DomainList dl2 = new DomainList().setNames(domainnames).setNext("next");
        assertTrue(dl2.equals(dl));
        assertTrue(dl.equals(dl));
        
        dl2.setNext(null);
        assertFalse(dl2.equals(dl));
        dl2.setNames(null);
        assertFalse(dl2.equals(dl));
        assertFalse(dl2.equals(null));
        assertFalse(dl.equals(new String()));
    }

    @Test
    public void testDomainMetaMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        DomainMeta dm = new DomainMeta().init();
        dm.setDescription("domain desc").setOrg("org:test").setEnabled(true).setAuditEnabled(false)
                .setAccount("user.test").setYpmId(10).setApplicationId("101")
                .setCertDnsDomain("athenz.cloud");

        Result result = validator.validate(dm, "DomainMeta");
        assertTrue(result.valid);

        assertEquals(dm.getDescription(), "domain desc");
        assertEquals(dm.getOrg(), "org:test");
        assertTrue(dm.getEnabled());
        assertFalse(dm.getAuditEnabled());
        assertEquals(dm.getAccount(), "user.test");
        assertEquals((int) dm.getYpmId(), 10);
        assertEquals(dm.getApplicationId(), "101");
        assertEquals(dm.getCertDnsDomain(), "athenz.cloud");

        DomainMeta dm2 = new DomainMeta().init();
        dm2.setDescription("domain desc").setOrg("org:test").setEnabled(true).setAuditEnabled(false)
                .setAccount("user.test").setYpmId(10).setApplicationId("101")
                .setCertDnsDomain("athenz.cloud");
        assertTrue(dm2.equals(dm));
        assertTrue(dm.equals(dm));

        dm2.setCertDnsDomain(null);
        assertFalse(dm2.equals(dm));
        dm2.setApplicationId(null);
        assertFalse(dm2.equals(dm));
        dm2.setYpmId(null);
        assertFalse(dm2.equals(dm));
        dm2.setAccount(null);
        assertFalse(dm2.equals(dm));
        dm2.setAuditEnabled(null);
        assertFalse(dm2.equals(dm));
        dm2.setEnabled(null);
        assertFalse(dm2.equals(dm));
        dm2.setOrg(null);
        assertFalse(dm2.equals(dm));
        dm2.setDescription(null);
        assertFalse(dm2.equals(dm));
        assertFalse(dm2.equals(null));
        assertFalse(dm.equals(new String()));

        // init will not reset false state

        dm2.setEnabled(false);
        dm2.setAuditEnabled(false);
        dm2.init();
        assertFalse(dm2.getAuditEnabled());
        assertFalse(dm2.getEnabled());
    }

    @Test
    public void testTopLevelDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> admins = Arrays.asList("test.admin1");

        // DomainTemplateList test
        List<String> templateNames = Arrays.asList("test");
        DomainTemplateList dtl = new DomainTemplateList().setTemplateNames(templateNames);

        Result result = validator.validate(dtl, "DomainTemplateList");
        assertTrue(result.valid);

        assertEquals(dtl.getTemplateNames(), templateNames);
        assertTrue(dtl.equals(dtl));
        assertFalse(dtl.equals(new DomainTemplateList()));

        // TopLevelDomain test
        TopLevelDomain tld = new TopLevelDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(dtl).setApplicationId("id1").setCertDnsDomain("athenz.cloud");

        result = validator.validate(tld, "TopLevelDomain");
        assertTrue(result.valid);

        assertEquals(tld.getDescription(), "domain desc");
        assertEquals(tld.getOrg(), "org:test");
        assertTrue(tld.getEnabled());
        assertFalse(tld.getAuditEnabled());
        assertEquals(tld.getAccount(), "user.test");
        assertEquals((int) tld.getYpmId(), 10);
        assertEquals(tld.getName(), "testdomain");
        assertEquals(tld.getAdminUsers(), admins);
        assertEquals(tld.getApplicationId(), "id1");
        assertNotNull(tld.getTemplates());
        assertEquals(tld.getCertDnsDomain(), "athenz.cloud");

        TopLevelDomain tld2 = new TopLevelDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(dtl).setApplicationId("id1").setCertDnsDomain("athenz.cloud");

        assertTrue(tld2.equals(tld));
        assertTrue(tld.equals(tld));

        tld2.setTemplates(null);
        assertFalse(tld2.equals(tld));
        tld2.setAdminUsers(null);
        assertFalse(tld2.equals(tld));
        tld2.setName(null);
        assertFalse(tld2.equals(tld));
        tld2.setCertDnsDomain(null);
        assertFalse(tld2.equals(tld));
        tld2.setApplicationId(null);
        assertFalse(tld2.equals(tld));
        tld2.setYpmId(null);
        assertFalse(tld2.equals(tld));
        tld2.setAccount(null);
        assertFalse(tld2.equals(tld));
        tld2.setAuditEnabled(null);
        assertFalse(tld2.equals(tld));
        tld2.setEnabled(null);
        assertFalse(tld2.equals(tld));
        tld2.setOrg(null);
        assertFalse(tld2.equals(tld));
        tld2.setDescription(null);
        assertFalse(tld2.equals(tld));
        assertFalse(tld2.equals(null));
        assertFalse(tld.equals(new String()));
    }

    @Test
    public void testSubDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> admins = Arrays.asList("test.admin1");

        SubDomain sd = new SubDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("vipng")))
                .setParent("domain.parent").setApplicationId("101").setCertDnsDomain("athenz.cloud");

        Result result = validator.validate(sd, "SubDomain");
        assertTrue(result.valid, result.error);

        assertEquals(sd.getDescription(), "domain desc");
        assertEquals(sd.getOrg(), "org:test");
        assertTrue(sd.getEnabled());
        assertFalse(sd.getAuditEnabled());
        assertEquals(sd.getAccount(), "user.test");
        assertEquals((int) sd.getYpmId(), 10);
        assertEquals(sd.getName(), "testdomain");
        assertEquals(sd.getAdminUsers(), admins);
        assertNotNull(sd.getTemplates());
        assertEquals(sd.getParent(), "domain.parent");
        assertEquals(sd.getApplicationId(), "101");
        assertEquals(sd.getCertDnsDomain(), "athenz.cloud");

        SubDomain sd2 = new SubDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("vipng")))
                .setParent("domain.parent").setApplicationId("101").setCertDnsDomain("athenz.cloud");

        assertTrue(sd2.equals(sd));
        assertTrue(sd.equals(sd));
        
        sd2.setParent(null);
        assertFalse(sd2.equals(sd));
        sd2.setTemplates(null);
        assertFalse(sd2.equals(sd));
        sd2.setAdminUsers(null);
        assertFalse(sd2.equals(sd));
        sd2.setName(null);
        assertFalse(sd2.equals(sd));
        sd2.setCertDnsDomain(null);
        assertFalse(sd2.equals(sd));
        sd2.setApplicationId(null);
        assertFalse(sd2.equals(sd));
        sd2.setYpmId(null);
        assertFalse(sd2.equals(sd));
        sd2.setAccount(null);
        assertFalse(sd2.equals(sd));
        sd2.setAuditEnabled(null);
        assertFalse(sd2.equals(sd));
        sd2.setEnabled(null);
        assertFalse(sd2.equals(sd));
        sd2.setOrg(null);
        assertFalse(sd2.equals(sd));
        sd2.setDescription(null);
        assertFalse(sd2.equals(sd));
        assertFalse(sd2.equals(null));
    }

    @Test
    public void testUserDomainMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        UserDomain ud = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testuser")
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("template")))
                .setApplicationId("101").setCertDnsDomain("athenz.cloud");

        Result result = validator.validate(ud, "UserDomain");
        assertTrue(result.valid);

        assertEquals(ud.getDescription(), "domain desc");
        assertEquals(ud.getOrg(), "org:test");
        assertTrue(ud.getEnabled());
        assertFalse(ud.getAuditEnabled());
        assertEquals(ud.getAccount(), "user.test");
        assertEquals((int) ud.getYpmId(), 10);
        assertEquals(ud.getName(), "testuser");
        assertEquals(ud.getApplicationId(), "101");
        assertNotNull(ud.getTemplates());
        assertEquals(ud.getCertDnsDomain(), "athenz.cloud");

        UserDomain ud2 = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testuser")
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("template")))
                .setApplicationId("101").setCertDnsDomain("athenz.cloud");

        assertTrue(ud2.equals(ud));
        assertTrue(ud.equals(ud));

        ud2.setTemplates(null);
        assertFalse(ud2.equals(ud));
        ud2.setName(null);
        assertFalse(ud2.equals(ud));
        ud2.setCertDnsDomain(null);
        assertFalse(ud2.equals(ud));
        ud2.setApplicationId(null);
        assertFalse(ud2.equals(ud));
        ud2.setYpmId(null);
        assertFalse(ud2.equals(ud));
        ud2.setAccount(null);
        assertFalse(ud2.equals(ud));
        ud2.setAuditEnabled(null);
        assertFalse(ud2.equals(ud));
        ud2.setEnabled(null);
        assertFalse(ud2.equals(ud));
        ud2.setOrg(null);
        assertFalse(ud2.equals(ud));
        ud2.setDescription(null);
        assertFalse(ud2.equals(ud));
        assertFalse(ud2.equals(null));
        assertFalse(ud.equals(new String()));
    }

    @Test
    public void testRoleMember() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        RoleMember rm = new RoleMember().setMemberName("user.test1").setExpiration(Timestamp.fromMillis(123456789123L));
        assertTrue(rm.equals(rm));

        Result result = validator.validate(rm, "RoleMember");
        assertTrue(result.valid);

        assertEquals(rm.getMemberName(), "user.test1");
        assertEquals(rm.getExpiration().millis(), 123456789123L);

        RoleMember rm2 = new RoleMember();
        assertFalse(rm2.equals(rm));

        rm2.setMemberName("user.test2");
        assertFalse(rm2.equals(rm));

        rm2.setMemberName("user.test1");
        assertFalse(rm2.equals(rm));

        rm2.setExpiration(Timestamp.fromMillis(123456789124L));
        assertFalse(rm2.equals(rm));
        rm2.setExpiration(Timestamp.fromMillis(123456789123L));
        assertTrue(rm2.equals(rm));

        assertFalse(rm2.equals(null));
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
    public void testDomainModifiedListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // DomainModified test
        DomainModified dm = new DomainModified().setName("test.domain")
                .setModified(123456789123L)
                .setAccount("1234")
                .setYpmId(1001);
        assertTrue(dm.equals(dm));

        Result result = validator.validate(dm, "DomainModified");
        assertTrue(result.valid);

        assertEquals(dm.getName(), "test.domain");
        assertEquals(dm.getModified(), 123456789123L);
        assertEquals(dm.getAccount(), "1234");
        assertEquals(dm.getYpmId().intValue(), 1001);

        DomainModified dm2 = new DomainModified().setName("test.domain")
                .setModified(123456789123L)
                .setAccount("1234")
                .setYpmId(1001);
        assertTrue(dm2.equals(dm));

        dm2.setYpmId(1002);
        assertFalse(dm2.equals(dm));
        dm2.setYpmId(null);
        assertFalse(dm2.equals(dm));

        dm2.setAccount("1235");
        assertFalse(dm2.equals(dm));
        dm2.setAccount(null);
        assertFalse(dm2.equals(dm));

        dm2.setModified(123456789124L);
        assertFalse(dm2.equals(dm));
        dm2.setModified(0);
        assertFalse(dm2.equals(dm));

        dm2.setName(null);
        assertFalse(dm2.equals(dm));

        assertFalse(dm2.equals(null));

        // DomainModifiedList test
        List<DomainModified> dml = Arrays.asList(dm);

        DomainModifiedList dmlist = new DomainModifiedList().setNameModList(dml);
        result = validator.validate(dmlist, "DomainModifiedList");
        assertTrue(result.valid);

        assertEquals(dmlist.getNameModList(), dml);

        DomainModifiedList dmlist2 = new DomainModifiedList().setNameModList(dml);
        assertTrue(dmlist2.equals(dmlist));
        assertTrue(dmlist.equals(dmlist));

        dmlist2.setNameModList(null);
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

        ms.setMemberName("test.member").setIsMember(false).setRoleName("test.role")
                .setExpiration(Timestamp.fromMillis(100));

        // init second time does not change state
        ms.init();
        assertFalse(ms.getIsMember());

        Result result = validator.validate(ms, "Membership");
        assertTrue(result.valid);

        assertEquals(ms.getMemberName(), "test.member");
        assertFalse(ms.getIsMember());
        assertEquals(ms.getRoleName(), "test.role");
        assertEquals(ms.getExpiration(), Timestamp.fromMillis(100));

        Membership ms2 = new Membership().setMemberName("test.member").setIsMember(false)
                .setExpiration(Timestamp.fromMillis(100)).setRoleName("test.role");

        assertTrue(ms2.equals(ms));
        assertTrue(ms.equals(ms));

        ms2.setExpiration(null);
        assertFalse(ms2.equals(ms));
        ms2.setRoleName(null);
        assertFalse(ms2.equals(ms));
        ms2.setIsMember(null);
        assertFalse(ms2.equals(ms));
        ms2.setMemberName(null);
        assertFalse(ms2.equals(ms));
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

        List<Policy> plist = Arrays.asList(new Policy().setName("test").setAssertions(Arrays.asList(a)));

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

        Tenancy t2 = new Tenancy().setDomain("test.domain").setService("test-service").setResourceGroups(rg);

        assertTrue(t2.equals(t));
        assertTrue(t.equals(t));

        t2.setResourceGroups(null);
        assertFalse(t2.equals(t));
        t2.setService(null);
        assertFalse(t2.equals(t));
        t2.setDomain(null);
        assertFalse(t2.equals(t));
        assertFalse(t2.equals(null));
        assertFalse(t.equals(new String()));
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

        List<ServiceIdentity> sl = new ArrayList<>();
        Template t = new Template().setRoles(rl).setPolicies(pl).setServices(sl);

        Result result = validator.validate(t, "Template");
        assertTrue(result.valid, result.error);

        assertEquals(t.getPolicies(), pl);
        assertEquals(t.getRoles(), rl);
        assertEquals(t.getServices(), sl);

        Template t2 = new Template().setRoles(rl).setPolicies(pl).setServices(sl);
        assertTrue(t2.equals(t));
        assertTrue(t.equals(t));

        t2.setServices(null);
        assertFalse(t2.equals(t));
        t2.setPolicies(null);
        assertFalse(t2.equals(t));
        t2.setRoles(null);
        assertFalse(t2.equals(t));

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

        assertTrue(prgr2.equals(prgr));
        assertTrue(prgr.equals(prgr));

        prgr2.setResourceGroup(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setRoles(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setTenant(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setService(null);
        assertFalse(prgr2.equals(prgr));
        prgr2.setDomain(null);
        assertFalse(prgr2.equals(prgr));
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
        assertEquals(Timestamp.fromMillis(100), quota.getModified());

        Quota quota2 = new Quota().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18)
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

        quota2.setName(null);
        assertFalse(quota2.equals(quota));
        quota2.setName("name2");
        assertFalse(quota2.equals(quota));

        assertFalse(quota2.equals(null));
        assertFalse(quota2.equals(new String()));
    }

    @Test
    public void testMemberRole() {

        MemberRole mbr1 = new MemberRole();
        mbr1.setRoleName("role1");
        mbr1.setExpiration(Timestamp.fromMillis(100));

        assertEquals("role1", mbr1.getRoleName());
        assertEquals(Timestamp.fromMillis(100), mbr1.getExpiration());

        assertTrue(mbr1.equals(mbr1));
        assertFalse(mbr1.equals(null));

        MemberRole mbr2 = new MemberRole();
        assertFalse(mbr2.equals(mbr1));

        mbr2.setRoleName("role2");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setRoleName("role1");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setExpiration(Timestamp.fromMillis(101));
        assertFalse(mbr2.equals(mbr1));

        mbr2.setExpiration(Timestamp.fromMillis(100));
        assertTrue(mbr2.equals(mbr1));
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
}

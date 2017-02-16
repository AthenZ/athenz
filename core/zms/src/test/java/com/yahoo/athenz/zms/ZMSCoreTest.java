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

        List<String> members = Arrays.asList("user:boynton");
        Role r = new Role().setName("sys.auth:role.admin").setMembers(members);
        Result result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("user.boynton"); // new
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        members = Arrays.asList("someuser@somecompany.com"); // not a valid principal
        r = new Role().setName("sys.auth:role.admin").setMembers(members);
        result = validator.validate(r, "Role");
        assertFalse(result.valid);
    }

    @Test
    public void testRolesMethod() {
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
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add");
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

        List<RoleAuditLog> rall = Arrays.asList(ral);

        // Role test
        List<String> members = Arrays.asList("user:boynton");
        Role r = new Role().setName("sys.auth:role.admin").setMembers(members)
                .setModified(Timestamp.fromMillis(123456789123L)).setTrust("domain.admin").setAuditLog(rall);
        result = validator.validate(r, "Role");
        assertTrue(result.valid);

        assertEquals(r.getName(), "sys.auth:role.admin");
        assertEquals(r.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(r.getMembers(), members);
        assertEquals(r.getTrust(), "domain.admin");
        assertEquals(r.getAuditLog(), rall);

        Role r2 = new Role().setName("sys.auth:role.admin").setMembers(members)
                .setModified(Timestamp.fromMillis(123456789123L)).setTrust("domain.admin");
        assertTrue(r.equals(r));
        
        r2.setAuditLog(null);
        assertFalse(r2.equals(r));
        r2.setTrust(null);
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
        Roles rs = new Roles().setList(rl);
        result = validator.validate(rs, "Roles");
        assertTrue(result.valid);

        assertEquals(rs.getList(), rl);

        assertTrue(rs.equals(rs));
        assertFalse(rs.equals(new Roles()));
        assertFalse(rs.equals(new String()));

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

        RoleList rl2 = new RoleList().setNames(names);

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
    public void testSignedDomainsMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Role r = new Role().setName("test.role");
        List<Role> rl = Arrays.asList(r);

        // assertion test
        Assertion a = new Assertion().setRole("test.role.*").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);
        Result result = validator.validate(a, "Assertion");
        assertTrue(result.valid);

        assertEquals(a.getRole(), "test.role.*");
        assertEquals(a.getResource(), "test.resource.*");
        assertEquals(a.getAction(), "test-action");
        assertEquals(a.getEffect(), AssertionEffect.fromString("ALLOW"));
        assertEquals((long) a.getId(), 0L);

        Assertion a2 = new Assertion().setRole("test.role.*").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW);
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

        List<Assertion> al = Arrays.asList(a);

        // Policy test
        Policy p = new Policy().setName("test-policy").setModified(Timestamp.fromMillis(123456789123L))
                .setAssertions(al);
        result = validator.validate(p, "Policy");
        assertTrue(result.valid);

        assertEquals(p.getName(), "test-policy");
        assertEquals(p.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(p.getAssertions(), al);

        Policy p2 = new Policy().setName("test-policy").setModified(Timestamp.fromMillis(123456789123L));
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
        result = validator.validate(pke, "PublicKeyEntry");
        assertTrue(result.valid);

        assertEquals(pke.getId(), "v1");
        assertEquals(pke.getKey(), "pubkey====");

        PublicKeyEntry pke2 = new PublicKeyEntry().setKey("pubkey====");
        assertTrue(pke.equals(pke));
        
        pke2.setId(null);
        assertFalse(pke2.equals(pke));
        pke2.setKey(null);
        assertFalse(pke2.equals(pke));
        assertFalse(pke.equals(new String()));

        // Entity test
        Entity e = new Entity().setName("test.entity").setValue(new Struct().with("key", "test"));
        result = validator.validate(e, "Entity");

        assertEquals(e.getName(), "test.entity");
        assertEquals(e.getValue(), new Struct().with("key", (Object) "test"));

        Entity e2 = new Entity().setName("test.entity");
        assertTrue(e.equals(e));
        
        e2.setValue(null);
        assertFalse(e2.equals(e));
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

        DomainPolicies dps2 = new DomainPolicies().setDomain("dps.domain");
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

        SignedPolicies sp2 = new SignedPolicies().setContents(dps).setSignature("zmssignature");
        assertTrue(sp.equals(sp));
        
        sp2.setKeyId(null);
        assertFalse(sp2.equals(sp));
        sp2.setSignature(null);
        assertFalse(sp2.equals(sp));
        sp2.setContents(null);
        assertFalse(sp2.equals(sp));
        assertFalse(sp.equals(new String()));

        List<PublicKeyEntry> pkel = Arrays.asList(pke);
        List<String> hosts = Arrays.asList("test.host");
        // ServiceIdentity test
        ServiceIdentity si = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test").setGroup("test.group");
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

        ServiceIdentity si2 = new ServiceIdentity().setName("test.service").setPublicKeys(pkel)
                .setProviderEndpoint("http://test.endpoint").setModified(Timestamp.fromMillis(123456789123L))
                .setExecutable("exec/path").setHosts(hosts).setUser("user.test");
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
        si2.setName(null);
        assertFalse(si2.equals(si));
        assertFalse(si.equals(new String()));

        List<ServiceIdentity> sil = Arrays.asList(si);
        List<Entity> el = Arrays.asList(e);

        // ServiceIdentities test
        ServiceIdentities sis = new ServiceIdentities().setList(sil);
        result = validator.validate(sis, "ServiceIdentities");
        assertTrue(result.valid);

        assertEquals(sis.getList(), sil);

        assertTrue(sis.equals(sis));
        assertFalse(sis.equals(new ServiceIdentities()));
        assertFalse(sis.equals(new String()));

        // DomainData test
        DomainData dd = new DomainData().setName("test.domain").setAccount("user.test").setYpmId(1).setRoles(rl)
                .setPolicies(sp).setServices(sil).setEntities(el).setModified(Timestamp.fromMillis(123456789123L));
        result = validator.validate(dd, "DomainData");
        assertTrue(result.valid);

        assertEquals(dd.getName(), "test.domain");
        assertEquals(dd.getAccount(), "user.test");
        assertEquals((int) dd.getYpmId(), 1);
        assertEquals(dd.getRoles(), rl);
        assertEquals(dd.getPolicies(), sp);
        assertEquals(dd.getServices(), sil);
        assertEquals(dd.getEntities(), el);
        assertEquals(dd.getModified(), Timestamp.fromMillis(123456789123L));

        DomainData dd2 = new DomainData().setName("test.domain").setAccount("user.test").setYpmId(1).setRoles(rl)
                .setPolicies(sp).setServices(sil).setEntities(el);
        assertTrue(dd.equals(dd));
        
        dd2.setModified(null);
        assertFalse(dd2.equals(dd));
        dd2.setEntities(null);
        assertFalse(dd2.equals(dd));
        dd2.setServices(null);
        assertFalse(dd2.equals(dd));
        dd2.setPolicies(null);
        assertFalse(dd2.equals(dd));
        dd2.setRoles(null);
        assertFalse(dd2.equals(dd));
        dd2.setYpmId(null);
        assertFalse(dd2.equals(dd));
        dd2.setAccount(null);
        assertFalse(dd2.equals(dd));
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

        SignedDomain sd2 = new SignedDomain().setDomain(dd).setSignature("zmssignature");
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
        SignedDomains sds = new SignedDomains().setDomains(sdl);
        result = validator.validate(sds, "SignedDomains");
        assertTrue(result.valid);

        assertEquals(sds.getDomains(), sdl);

        assertTrue(sds.equals(sds));
        assertFalse(sds.equals(new SignedDomains()));
        assertFalse(sds.equals(new String()));

    }

    @Test
    public void testAccess() {
        Access a = new Access().setGranted(true);
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(a, "Access");
        assertTrue(result.valid);

        Access a2 = new Access().setGranted(false);
        assertEquals(a.getGranted(), true);

        assertTrue(a.equals(a));
        
        assertFalse(a.equals(a2));
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

        DanglingPolicy dlp2 = new DanglingPolicy().setPolicyName("test.policy");
        assertTrue(dlp.equals(dlp));
        
        dlp2.setRoleName(null);
        assertFalse(dlp2.equals(dlp));
        dlp2.setPolicyName(null);
        assertFalse(dlp2.equals(dlp));

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
                .setAssertionCount(10).setRoleWildCardCount(10).setProvidersWithoutTrust(pwt);
        assertTrue(ddc.equals(ddc));
        
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

        Domain d = new Domain().init();
        d.setName("test.domain").setModified(Timestamp.fromMillis(123456789123L)).setId(UUID.fromString("test-id"))
                .setDescription("test desc").setOrg("test-org").setEnabled(true).setAuditEnabled(true)
                .setAccount("user.test").setYpmId(1);
        Result result = validator.validate(d, "Domain");
        assertTrue(result.valid);

        assertEquals(d.getName(), "test.domain");
        assertEquals(d.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(d.getId(), UUID.fromString("test-id"));
        assertEquals(d.getDescription(), "test desc");
        assertEquals(d.getOrg(), "test-org");
        assertTrue(d.getEnabled());
        assertTrue(d.getAuditEnabled());
        assertEquals(d.getAccount(), "user.test");
        assertEquals((int) d.getYpmId(), 1);

        Domain d2 = new Domain().setName("test.domain").setModified(Timestamp.fromMillis(123456789123L))
                .setId(UUID.fromString("test-id")).setDescription("test desc").setOrg("test-org").setEnabled(true)
                .setAuditEnabled(true).setAccount("user.test");

        assertTrue(d.equals(d));
        
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
        d2.setId(null);
        assertFalse(d2.equals(d));
        d2.setModified(null);
        assertFalse(d2.equals(d));
        d2.setName(null);
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

        DomainList dl2 = new DomainList().setNames(domainnames);
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
                .setAccount("user.test").setYpmId(10);

        Result result = validator.validate(dm, "DomainMeta");
        assertTrue(result.valid);

        assertEquals(dm.getDescription(), "domain desc");
        assertEquals(dm.getOrg(), "org:test");
        assertTrue(dm.getEnabled());
        assertFalse(dm.getAuditEnabled());
        assertEquals(dm.getAccount(), "user.test");
        assertEquals((int) dm.getYpmId(), 10);

        DomainMeta dm2 = new DomainMeta().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test");
        assertTrue(dm.equals(dm));
        
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
                .setTemplates(dtl);

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
        assertNotNull(tld.getTemplates());

        TopLevelDomain tld2 = new TopLevelDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testdomain")
                .setAdminUsers(admins);

        assertTrue(tld.equals(tld));
        
        tld2.setTemplates(null);
        assertFalse(tld2.equals(tld));
        tld2.setAdminUsers(null);
        assertFalse(tld2.equals(tld));
        tld2.setName(null);
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
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("test.template")))
                .setParent("domain.parent");

        Result result = validator.validate(sd, "SubDomain");
        assertTrue(result.valid);

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

        SubDomain sd2 = new SubDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testdomain").setAdminUsers(admins)
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("test.template")))
                .setParent("domain.parent2");

        assertTrue(sd.equals(sd));
        
        sd2.setParent(null);
        assertFalse(sd2.equals(sd));
        sd2.setTemplates(null);
        assertFalse(sd2.equals(sd));
        sd2.setAdminUsers(null);
        assertFalse(sd2.equals(sd));
        sd2.setName(null);
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
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("template")));

        Result result = validator.validate(ud, "UserDomain");
        assertTrue(result.valid);

        assertEquals(ud.getDescription(), "domain desc");
        assertEquals(ud.getOrg(), "org:test");
        assertTrue(ud.getEnabled());
        assertFalse(ud.getAuditEnabled());
        assertEquals(ud.getAccount(), "user.test");
        assertEquals((int) ud.getYpmId(), 10);
        assertEquals(ud.getName(), "testuser");
        assertNotNull(ud.getTemplates());

        UserDomain ud2 = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testuser");

        assertTrue(ud.equals(ud));
        
        ud2.setTemplates(null);
        assertFalse(ud2.equals(ud));
        ud2.setName(null);
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
    public void testDomainModifiedListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // DomainModified test
        DomainModified dm = new DomainModified().setName("test.domain").setModified(123456789123L);

        Result result = validator.validate(dm, "DomainModified");
        assertTrue(result.valid);

        assertEquals(dm.getName(), "test.domain");
        assertEquals(dm.getModified(), 123456789123L);

        DomainModified dm2 = new DomainModified().setName("test.domain");
        assertTrue(dm.equals(dm));
        
        dm2.setModified(123456789124L);
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

        assertTrue(dmlist.equals(dmlist));
        assertFalse(dmlist.equals(new DomainModifiedList()));
    }

    @Test
    public void testDomainTemplateMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> dl = Arrays.asList("user_provisioning");

        DomainTemplate dt = new DomainTemplate().setTemplateNames(dl);
        Result result = validator.validate(dt, "DomainTemplate");
        assertTrue(result.valid);

        assertEquals(dt.getTemplateNames(), dl);

        DomainTemplate dt2 = new DomainTemplate();
        assertTrue(dt.equals(dt));
        assertFalse(dt.equals(dt2));
        assertFalse(dt.equals(null));
        assertFalse(dt.equals(new String()));
    }

    @Test
    public void testMembershipMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Membership ms = new Membership().init();
        ms.setMemberName("test.member").setIsMember(false).setRoleName("test.role");

        Result result = validator.validate(ms, "Membership");
        assertTrue(result.valid);

        assertEquals(ms.getMemberName(), "test.member");
        assertFalse(ms.getIsMember());
        assertEquals(ms.getRoleName(), "test.role");

        Membership ms2 = new Membership().setMemberName("test.member").setIsMember(false);
        assertTrue(ms.equals(ms));
        
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

        DefaultAdmins da2 = new DefaultAdmins();
        assertTrue(da.equals(da));
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

        PolicyList pl2 = new PolicyList().setNames(plist);
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

        ServiceIdentityList sil2 = new ServiceIdentityList().setNames(slist);
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

        TemplateList tl2 = new TemplateList();
        assertTrue(tl.equals(tl));
        assertFalse(tl.equals(tl2));
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

        DomainTemplate tl2 = new DomainTemplate();
        assertTrue(tl.equals(tl));
        assertFalse(tl.equals(tl2));
        assertFalse(tl.equals(new String()));

    }

    @Test
    public void testServerTemplateListMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<String> tnames = Arrays.asList("testtemplate");

        ServerTemplateList tl = new ServerTemplateList().setTemplateNames(tnames);

        Result result = validator.validate(tl, "ServerTemplateList");
        assertTrue(result.valid);

        assertEquals(tl.getTemplateNames(), tnames);

        ServerTemplateList tl2 = new ServerTemplateList();
        assertTrue(tl.equals(tl));
        assertFalse(tl.equals(tl2));
        assertFalse(tl.equals(new String()));

    }

    @Test
    public void testUserTokenMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        UserToken ut = new UserToken().setToken("testtoken");

        Result result = validator.validate(ut, "UserToken");
        assertTrue(result.valid);

        assertEquals(ut.getToken(), "testtoken");

        UserToken ut2 = new UserToken().setToken("test");
        assertTrue(ut.equals(ut));
        assertFalse(ut.equals(ut2));
        assertFalse(ut.equals(new String()));
    }

    @Test
    public void testTenantRolesMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // TenantRoleAction test
        TenantRoleAction tra = new TenantRoleAction().setRole("testrole").setAction("add");
        Result result = validator.validate(tra, "TenantRoleAction");
        assertTrue(result.valid);

        assertEquals(tra.getRole(), "testrole");
        assertEquals(tra.getAction(), "add");

        TenantRoleAction tra2 = new TenantRoleAction().setRole("testrole");
        assertTrue(tra.equals(tra));
        
        tra2.setAction(null);
        assertFalse(tra2.equals(tra));
        tra2.setRole(null);
        assertFalse(tra2.equals(tra));
        assertFalse(tra.equals(new String()));

        // TenantRoles test
        List<TenantRoleAction> tral = Arrays.asList(tra);
        TenantRoles tr = new TenantRoles().setDomain("test.provider.domain").setService("testservice")
                .setTenant("test.tenant").setRoles(tral);

        result = validator.validate(tr, "TenantRoles");
        assertTrue(result.valid);

        assertEquals(tr.getDomain(), "test.provider.domain");
        assertEquals(tr.getService(), "testservice");
        assertEquals(tr.getTenant(), "test.tenant");
        assertEquals(tr.getRoles(), tral);

        TenantRoles tr2 = new TenantRoles().setDomain("test.provider.domain").setService("testservice")
                .setTenant("test.tenant");
        assertTrue(tr.equals(tr));
        
        tr2.setRoles(null);
        assertFalse(tr2.equals(tr));
        tr2.setTenant(null);
        assertFalse(tr2.equals(tr));
        tr2.setService(null);
        assertFalse(tr2.equals(tr));
        tr2.setDomain(null);
        assertFalse(tr2.equals(tr));
        assertFalse(tr2.equals(null));
        assertFalse(tr.equals(new String()));

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

        EntityList el2 = new EntityList();
        assertTrue(el.equals(el));
        assertFalse(el.equals(el2));
        assertFalse(el.equals(new String()));

    }

    @Test
    public void testPoliciesMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Assertion a = new Assertion().setRole("test.role.*").setResource("test.resource.*").setAction("test-action")
                .setEffect(AssertionEffect.ALLOW).setId(0L);

        List<Policy> plist = Arrays.asList(new Policy().setName("test").setAssertions(Arrays.asList(a)));

        Policies ps = new Policies().setList(plist);

        Result result = validator.validate(ps, "Policies");
        assertTrue(result.valid);

        assertEquals(ps.getList(), plist);

        Policies ps2 = new Policies();
        assertTrue(ps.equals(ps));
        assertFalse(ps.equals(ps2));
        assertFalse(ps.equals(new String()));

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

        Tenancy t2 = new Tenancy().setDomain("test.domain").setService("test-service");
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
    public void testTenancyResourceGroupMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        TenancyResourceGroup trg = new TenancyResourceGroup().setDomain("test.domain").setService("test-service")
                .setResourceGroup("test.group");

        Result result = validator.validate(trg, "TenancyResourceGroup");
        assertTrue(result.valid);

        assertEquals(trg.getDomain(), "test.domain");
        assertEquals(trg.getService(), "test-service");
        assertEquals(trg.getResourceGroup(), "test.group");

        TenancyResourceGroup trg2 = new TenancyResourceGroup().setDomain("test.domain").setService("test-service");
        assertTrue(trg.equals(trg));
        
        trg2.setResourceGroup(null);
        assertFalse(trg2.equals(trg));
        trg2.setService(null);
        assertFalse(trg2.equals(trg));
        trg2.setDomain(null);
        assertFalse(trg2.equals(trg));
        assertFalse(trg2.equals(null));
        assertFalse(trg2.equals(new String()));
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

        ResourceAccess ra2 = new ResourceAccess().setPrincipal("test.principal");
        assertTrue(ra.equals(ra));
        
        ra2.setAssertions(null);
        assertFalse(ra2.equals(ra));
        ra2.setPrincipal(null);
        assertFalse(ra2.equals(ra));
        assertFalse(ra.equals(new String()));

        // ResourceAccessList test
        List<ResourceAccess> ralist = Arrays.asList(ra);
        ResourceAccessList ral = new ResourceAccessList().setResources(ralist);
        result = validator.validate(ral, "ResourceAccessList");
        assertTrue(result.valid);

        assertEquals(ral.getResources(), ralist);

        assertTrue(ral.equals(ral));
        assertFalse(ral.equals(new ResourceAccessList()));
        assertFalse(ral.equals(null));
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

        ServicePrincipal sp2 = new ServicePrincipal().setDomain("test.domain").setService("test-service");
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

        List<Role> rl = Arrays.asList(new Role().setName("sys.auth:role.admin").setMembers(Arrays.asList("test")));
        List<Policy> pl = Arrays
                .asList(new Policy().setName("test-policy").setModified(Timestamp.fromMillis(123456789123L)));
        Template t = new Template().setRoles(rl).setPolicies(pl);

        Result result = validator.validate(t, "Template");
        assertTrue(result.valid);

        assertEquals(t.getPolicies(), pl);
        assertEquals(t.getRoles(), rl);

        Template t2 = new Template().setRoles(rl);
        assertTrue(t.equals(t));
        
        t2.setRoles(null);
        assertFalse(t2.equals(t));
        t2.setPolicies(null);
        assertFalse(t2.equals(t));
        assertFalse(t2.equals(null));
        assertFalse(t.equals(new String()));

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
                .setService("test-service").setTenant("test.tenant").setRoles(tral);
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
                .setService("test-service").setTenant("test.domain").setRoles(tral);

        assertTrue(trgr.equals(trgr));
        
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

}

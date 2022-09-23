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

package com.yahoo.athenz.zts;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

import static org.testng.Assert.*;

public class DomainSignedPolicyDataTest {

    @Test
    public void testsetgetSignedPolicyData() {

        DomainSignedPolicyData dspd = new DomainSignedPolicyData();
        DomainSignedPolicyData dspd2 = new DomainSignedPolicyData();

        SignedPolicyData spd = new SignedPolicyData();
        SignedPolicyData spd2 = new SignedPolicyData();

        PolicyData pd = new PolicyData();
        PolicyData pd2 = new PolicyData();

        Policy p = new Policy();
        Policy p2 = new Policy();

        Assertion a = new Assertion();
        Assertion a2 = new Assertion();

        // set assertion
        a.setRole("user.hoge:role.test");
        a.setResource("user.hoge:coffee.blends.*");
        a.setAction("read");
        a.setEffect(AssertionEffect.ALLOW);
        a.setId(0L);

        a2.setRole("user.hoge:role.test");
        a2.setResource("user.hoge:coffee.blends.*");
        a2.setAction("read");
        a2.setEffect(AssertionEffect.ALLOW);

        List<Assertion> al = new ArrayList<>();
        al.add(a);

        // set policy
        p.setName("test_policy");
        p.setModified(Timestamp.fromMillis(1234567890123L));
        p.setAssertions(al);

        p2.setName("test_policy");
        p2.setModified(Timestamp.fromMillis(1234567890123L));

        List<Policy> pl = new ArrayList<>();
        pl.add(p);

        // set policy data
        pd.setDomain("user.hoge");
        pd.setPolicies(pl);

        pd2.setDomain("user.hoge");

        // set signed policy data
        spd.setExpires(Timestamp.fromMillis(1234567890123L));
        spd.setModified(Timestamp.fromMillis(1234567890123L));
        spd.setPolicyData(pd);
        spd.setZmsKeyId("zmsid");
        spd.setZmsSignature("signature");

        spd2.setModified(Timestamp.fromMillis(1234567890123L));
        spd2.setPolicyData(pd);
        spd2.setZmsKeyId("zmsid");
        spd2.setZmsSignature("signature");

        // set domain signed policy data
        dspd.setKeyId("kid");
        dspd.setSignature("signature");
        dspd.setSignedPolicyData(spd);

        dspd2.setSignature("signature");
        dspd2.setSignedPolicyData(spd);

        // get assertion
        assertEquals(a.getRole(), "user.hoge:role.test");
        assertEquals(a.getResource(), "user.hoge:coffee.blends.*");
        assertEquals((long) a.getId(), 0L);
        assertEquals(a.getEffect(), AssertionEffect.ALLOW);
        assertEquals(a.getAction(), "read");

        // get policy
        assertEquals(p.getAssertions(), al);
        assertEquals(p.getModified(), Timestamp.fromMillis(1234567890123L));
        assertEquals(p.getName(), "test_policy");

        // get policy data
        assertEquals(pd.getDomain(), "user.hoge");
        assertEquals(pd.getPolicies(), pl);

        // get signed policy data
        assertEquals(spd.getExpires(), Timestamp.fromMillis(1234567890123L));
        assertEquals(spd.getModified(), Timestamp.fromMillis(1234567890123L));
        assertEquals(spd.getPolicyData(), pd);
        assertEquals(spd.getZmsKeyId(), "zmsid");
        assertEquals(spd.getZmsSignature(), "signature");

        // get domain signed policy data
        assertEquals(dspd.getKeyId(), "kid");
        assertEquals(dspd.getSignature(), "signature");
        assertEquals(dspd.getSignedPolicyData(), spd);

        // equals true
        assertEquals(a, a);
        assertEquals(p, p);
        assertEquals(pd, pd);
        assertEquals(spd, spd);
        assertEquals(dspd, dspd);

        // equals false
        assertNotEquals(a2, a);
        a2.setEffect(null);
        assertNotEquals(a2, a);
        a2.setAction(null);
        assertNotEquals(a2, a);
        a2.setResource(null);
        assertNotEquals(a2, a);
        a2.setRole(null);
        assertNotEquals(a2, a);

        assertNotEquals(p2, p);
        p2.setModified(null);
        assertNotEquals(p2, p);
        p2.setName(null);
        assertNotEquals(p2, p);

        assertNotEquals(pd2, pd);
        pd2.setDomain(null);
        assertNotEquals(pd2, pd);

        assertNotEquals(spd2, spd);
        spd2.setModified(null);
        assertNotEquals(spd2, spd);
        spd2.setZmsKeyId(null);
        assertNotEquals(spd2, spd);
        spd2.setZmsSignature(null);
        assertNotEquals(spd2, spd);
        spd2.setPolicyData(null);
        assertNotEquals(spd2, spd);

        assertNotEquals(dspd2, dspd);
        dspd2.setSignature(null);
        assertNotEquals(dspd2, dspd);
        dspd2.setSignedPolicyData(null);
        assertNotEquals(dspd2, dspd);

        assertNotEquals("", a);
        assertNotEquals("", p);
        assertNotEquals("", pd);
        assertNotEquals("", spd);
        assertNotEquals("", dspd);
    }

    @Test
    public void testPolicy() {

        Policy data1 = new Policy();
        data1.setAssertions(Collections.emptyList());
        data1.setModified(Timestamp.fromMillis(100));
        data1.setName("name");
        data1.setCaseSensitive(Boolean.FALSE);

        Policy data2 = new Policy();
        data2.setAssertions(Collections.emptyList());
        data2.setModified(Timestamp.fromMillis(100));
        data2.setName("name");
        data2.setCaseSensitive(Boolean.FALSE);

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        // verify getters
        assertEquals("name", data2.getName());
        assertEquals(Collections.emptyList(), data2.getAssertions());
        assertEquals(Timestamp.fromMillis(100), data2.getModified());
        assertEquals(Boolean.FALSE, data2.getCaseSensitive());

        data2.setName("name2");
        assertNotEquals(data1, data2);
        data2.setName(null);
        assertNotEquals(data1, data2);
        data2.setName("name");

        data2.setModified(Timestamp.fromMillis(101));
        assertNotEquals(data1, data2);
        data2.setModified(null);
        assertNotEquals(data1, data2);
        data2.setModified(Timestamp.fromMillis(100));

        data2.setCaseSensitive(Boolean.TRUE);
        assertNotEquals(data1, data2);
        data2.setCaseSensitive(null);
        assertNotEquals(data1, data2);
        data2.setCaseSensitive(Boolean.FALSE);

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion());

        data2.setAssertions(assertions);
        assertNotEquals(data1, data2);
        data2.setAssertions(null);
        assertNotEquals(data1, data2);
        data2.setAssertions(Collections.emptyList());

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }

    @Test
    public void testAssertion() {

        Assertion data1 = new Assertion();
        data1.setAction("action");
        data1.setEffect(AssertionEffect.ALLOW);
        data1.setResource("resource");
        data1.setId(100L);
        data1.setRole("role");
        data1.setCaseSensitive(Boolean.FALSE);

        Assertion data2 = new Assertion();
        data2.setAction("action");
        data2.setEffect(AssertionEffect.ALLOW);
        data2.setResource("resource");
        data2.setId(100L);
        data2.setRole("role");
        data2.setCaseSensitive(Boolean.FALSE);

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        // verify getters
        assertEquals("action", data2.getAction());
        assertEquals("resource", data2.getResource());
        assertEquals("role", data2.getRole());
        assertEquals(AssertionEffect.ALLOW, data2.getEffect());
        assertEquals(100L, (long) data2.getId());
        assertEquals(Boolean.FALSE, data2.getCaseSensitive());

        data2.setAction("action2");
        assertNotEquals(data1, data2);
        data2.setAction(null);
        assertNotEquals(data1, data2);
        data2.setAction("action");

        data2.setResource("resource2");
        assertNotEquals(data1, data2);
        data2.setResource(null);
        assertNotEquals(data1, data2);
        data2.setResource("resource");

        data2.setRole("role2");
        assertNotEquals(data1, data2);
        data2.setRole(null);
        assertNotEquals(data1, data2);
        data2.setRole("role");

        data2.setCaseSensitive(Boolean.TRUE);
        assertNotEquals(data1, data2);
        data2.setCaseSensitive(null);
        assertNotEquals(data1, data2);
        data2.setCaseSensitive(Boolean.FALSE);

        data2.setEffect(AssertionEffect.DENY);
        assertNotEquals(data1, data2);
        data2.setEffect(null);
        assertNotEquals(data1, data2);
        data2.setEffect(AssertionEffect.ALLOW);

        data2.setId(1002L);
        assertNotEquals(data1, data2);
        data2.setId(null);
        assertNotEquals(data1, data2);
        data2.setId(100L);

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }

    @Test
    public void testPolicyData() {
        PolicyData pd1 = new PolicyData();
        PolicyData pd2 = new PolicyData();

        pd1.setPolicies(Collections.singletonList(new Policy()));
        pd1.setDomain("domainA");

        pd2.setPolicies(Collections.singletonList(new Policy()));
        pd2.setDomain("domainA");

        assertEquals(Collections.singletonList(new Policy()), pd1.getPolicies());
        assertEquals("domainA", pd1.getDomain());

        assertEquals(pd1, pd2);
        assertEquals(pd1, pd1);

        pd1.setPolicies(Collections.singletonList(new Policy().setName("pl1")));
        assertNotEquals(pd2, pd1);
        pd1.setPolicies(null);
        assertNotEquals(pd2, pd1);
        pd1.setPolicies(Collections.singletonList(new Policy()));
        assertEquals(pd2, pd1);

        pd1.setDomain("domainB");
        assertNotEquals(pd2, pd1);
        pd1.setDomain(null);
        assertNotEquals(pd2, pd1);
        pd1.setDomain("domainA");
        assertEquals(pd2, pd1);

        assertNotEquals(pd2, null);
        assertNotEquals("pd2", pd1);
    }

    @Test
    public void testDomainSignedPolicyData() {

        DomainSignedPolicyData dspd1 = new DomainSignedPolicyData();
        DomainSignedPolicyData dspd2 = new DomainSignedPolicyData();

        dspd1.setKeyId("kid");
        dspd1.setSignature("signature");
        dspd1.setSignedPolicyData(new SignedPolicyData());

        dspd2.setKeyId("kid");
        dspd2.setSignature("signature");
        dspd2.setSignedPolicyData(new SignedPolicyData());

        assertEquals(dspd1, dspd2);
        assertEquals(dspd1, dspd1);

        assertEquals(dspd1.getSignature(), "signature");
        assertEquals(dspd1.getKeyId(), "kid");
        assertEquals(dspd1.getSignedPolicyData(), new SignedPolicyData());

        dspd1.setKeyId("kid2");
        assertNotEquals(dspd2, dspd1);
        dspd1.setKeyId(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setKeyId("kid");
        assertEquals(dspd2, dspd1);

        dspd1.setSignature("signature1");
        assertNotEquals(dspd2, dspd1);
        dspd1.setSignature(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setSignature("signature");
        assertEquals(dspd2, dspd1);

        dspd1.setSignedPolicyData(new SignedPolicyData().setZmsKeyId("kid"));
        assertNotEquals(dspd2, dspd1);
        dspd1.setSignedPolicyData(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setSignedPolicyData(new SignedPolicyData());
        assertEquals(dspd2, dspd1);

        assertNotEquals(dspd2, null);
        assertNotEquals("dspd2", dspd2);
    }

    @Test
    public void testSignedPolicyData() {

        SignedPolicyData dspd1 = new SignedPolicyData();
        SignedPolicyData dspd2 = new SignedPolicyData();

        dspd1.setZmsKeyId("kid");
        dspd1.setZmsSignature("signature");
        dspd1.setExpires(Timestamp.fromMillis(123456789123L));
        dspd1.setModified(Timestamp.fromMillis(123456789123L));
        dspd1.setPolicyData(new PolicyData());

        dspd2.setZmsKeyId("kid");
        dspd2.setZmsSignature("signature");
        dspd2.setExpires(Timestamp.fromMillis(123456789123L));
        dspd2.setModified(Timestamp.fromMillis(123456789123L));
        dspd2.setPolicyData(new PolicyData());

        assertEquals(dspd1, dspd2);
        assertEquals(dspd1, dspd1);

        assertEquals(dspd1.getZmsSignature(), "signature");
        assertEquals(dspd1.getZmsKeyId(), "kid");
        assertEquals(dspd1.getExpires(), Timestamp.fromMillis(123456789123L));
        assertEquals(dspd1.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(dspd1.getPolicyData(), new PolicyData());

        dspd1.setZmsKeyId("kid2");
        assertNotEquals(dspd2, dspd1);
        dspd1.setZmsKeyId(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setZmsKeyId("kid");
        assertEquals(dspd2, dspd1);

        dspd1.setZmsSignature("signature1");
        assertNotEquals(dspd2, dspd1);
        dspd1.setZmsSignature(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setZmsSignature("signature");
        assertEquals(dspd2, dspd1);

        dspd1.setPolicyData(new PolicyData().setDomain("domain"));
        assertNotEquals(dspd2, dspd1);
        dspd1.setPolicyData(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setPolicyData(new PolicyData());
        assertEquals(dspd2, dspd1);

        dspd1.setExpires(Timestamp.fromMillis(123456789124L));
        assertNotEquals(dspd2, dspd1);
        dspd1.setExpires(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setExpires(Timestamp.fromMillis(123456789123L));
        assertEquals(dspd2, dspd1);

        dspd1.setModified(Timestamp.fromMillis(123456789124L));
        assertNotEquals(dspd2, dspd1);
        dspd1.setModified(null);
        assertNotEquals(dspd2, dspd1);
        dspd1.setModified(Timestamp.fromMillis(123456789123L));
        assertEquals(dspd2, dspd1);

        assertNotEquals(dspd2, null);
        assertNotEquals("dspd2", dspd2);
    }

}

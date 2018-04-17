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

package com.yahoo.athenz.zts;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

import static org.testng.Assert.*;

@SuppressWarnings({"EqualsWithItself", "EqualsBetweenInconvertibleTypes"})
public class DomainSignedPolicyDataTest implements Cloneable {

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

        //// set
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

        //// get assertion
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

}

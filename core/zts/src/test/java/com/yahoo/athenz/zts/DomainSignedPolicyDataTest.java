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

package com.yahoo.athenz.zts;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

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

        List<Assertion> al = new ArrayList<Assertion>();
        al.add(a);

        // set policy
        p.setName("test_policy");
        p.setModified(Timestamp.fromMillis(1234567890123L));
        p.setAssertions(al);

        p2.setName("test_policy");
        p2.setModified(Timestamp.fromMillis(1234567890123L));

        List<Policy> pl = new ArrayList<Policy>();
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
        assertTrue(a.equals(a));
        assertTrue(p.equals(p));
        assertTrue(pd.equals(pd));
        assertTrue(spd.equals(spd));
        assertTrue(dspd.equals(dspd));

        // equals false
        assertFalse(a2.equals(a));
        a2.setEffect(null);
        assertFalse(a2.equals(a));
        a2.setAction(null);
        assertFalse(a2.equals(a));
        a2.setResource(null);
        assertFalse(a2.equals(a));
        a2.setRole(null);
        assertFalse(a2.equals(a));
        
        
        assertFalse(p2.equals(p));
        p2.setModified(null);
        assertFalse(p2.equals(p));
        p2.setName(null);
        assertFalse(p2.equals(p));
        
        assertFalse(pd2.equals(pd));
        pd2.setDomain(null);
        assertFalse(pd2.equals(pd));
        
        assertFalse(spd2.equals(spd));
        spd2.setModified(null);
        assertFalse(spd2.equals(spd));
        spd2.setZmsKeyId(null);
        assertFalse(spd2.equals(spd));
        spd2.setZmsSignature(null);
        assertFalse(spd2.equals(spd));
        spd2.setPolicyData(null);
        assertFalse(spd2.equals(spd));
        
        assertFalse(dspd2.equals(dspd));
        dspd2.setSignature(null);
        assertFalse(dspd2.equals(dspd));
        dspd2.setSignedPolicyData(null);
        assertFalse(dspd2.equals(dspd));
        
        assertFalse(a.equals(new String()));
        assertFalse(p.equals(new String()));
        assertFalse(pd.equals(new String()));
        assertFalse(spd.equals(new String()));
        assertFalse(dspd.equals(new String()));

    }

}

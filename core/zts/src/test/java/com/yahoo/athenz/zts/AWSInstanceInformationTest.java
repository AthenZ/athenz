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

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

public class AWSInstanceInformationTest {

    @Test
    public void testIdentity() {
        AWSInstanceInformation i = new AWSInstanceInformation();
        AWSInstanceInformation i2 = new AWSInstanceInformation();

        // set
        i.setDocument("test_doc");
        i.setSignature("test_sig");
        i.setDomain("test.domain");
        i.setService("test.service");
        i.setCsr("test.csr");
        i.setName("test.name");
        i.setAccount("user.test");
        i.setAccess("test.access");
        i.setCloud("test.cloud");
        i.setSubnet("test.subnet");
        i.setSecret("test.secret");
        i.setToken("test.token");
        i.setExpires(Timestamp.fromMillis(123456789123L));
        i.setModified(Timestamp.fromMillis(123456789122L));
        i.setFlavor("test.flavor");

        i2.setDocument("test_doc");
        i2.setSignature("test_sig");
        i2.setDomain("test.domain");
        i2.setService("test.service");
        i2.setCsr("test.csr");
        i2.setName("test.name");
        i2.setAccount("user.test");
        i2.setAccess("test.access");
        i2.setCloud("test.cloud");
        i2.setSubnet("test.subnet");
        i2.setSecret("test.secret");
        i2.setToken("test.token");
        i2.setExpires(Timestamp.fromMillis(123456789123L));
        i2.setModified(Timestamp.fromMillis(123456789122L));

        // getter assertion
        assertEquals(i.getDocument(), "test_doc");
        assertEquals(i.getSignature(), "test_sig");
        assertEquals(i.getDomain(), "test.domain");
        assertEquals(i.getService(), "test.service");
        assertEquals(i.getCsr(), "test.csr");
        assertEquals(i.getName(), "test.name");
        assertEquals(i.getAccount(), "user.test");
        assertEquals(i.getAccess(), "test.access");
        assertEquals(i.getCloud(), "test.cloud");
        assertEquals(i.getSubnet(), "test.subnet");
        assertEquals(i.getSecret(), "test.secret");
        assertEquals(i.getToken(), "test.token");
        assertEquals(i.getExpires(), Timestamp.fromMillis(123456789123L));
        assertEquals(i.getModified(), Timestamp.fromMillis(123456789122L));
        assertEquals(i.getFlavor(), "test.flavor");

        assertTrue(i.equals(i));
        
        assertFalse(i2.equals(i));
        i2.setModified(null);
        assertFalse(i2.equals(i));
        i2.setExpires(null);
        assertFalse(i2.equals(i));
        i2.setToken(null);
        assertFalse(i2.equals(i));
        i2.setSecret(null);
        assertFalse(i2.equals(i));
        i2.setAccess(null);
        assertFalse(i2.equals(i));
        i2.setSubnet(null);
        assertFalse(i2.equals(i));
        i2.setCloud(null);
        assertFalse(i2.equals(i));
        i2.setAccount(null);
        assertFalse(i2.equals(i));
        i2.setName(null);
        assertFalse(i2.equals(i));
        i2.setCsr(null);
        assertFalse(i2.equals(i));
        i2.setService(null);
        assertFalse(i2.equals(i));
        i2.setDomain(null);
        assertFalse(i2.equals(i));
        i2.setSignature(null);
        assertFalse(i2.equals(i));
        i2.setDocument(null);
        assertFalse(i2.equals(i));
        
        assertFalse(i.equals(new String()));
    }

}

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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

@SuppressWarnings("EqualsBetweenInconvertibleTypes")
public class InstanceInformationTest {

    @Test
    public void testInstanceInformation() {
        InstanceInformation i = new InstanceInformation();
        InstanceInformation i2 = new InstanceInformation();

        // set
        i.setDocument("doc");
        i.setSignature("sig");
        i.setDomain("sample.com");
        i.setService("sample.service");
        i.setCsr("sample_csr");
        i2.setDocument("doc");
        i2.setSignature("sig");
        i2.setDomain("sample.com");
        i2.setService("sample.service");
        i2.setCsr("sample_csr");

        // getter assertion
        assertEquals(i.getDocument(), "doc");
        assertEquals(i.getSignature(), "sig");
        assertEquals(i.getDomain(), "sample.com");
        assertEquals(i.getService(), "sample.service");
        assertEquals(i.getCsr(), "sample_csr");

        assertEquals(i2, i);
        
        i2.setService(null);
        assertNotEquals(i2, i);
        i2.setService("sample.service");

        i2.setDomain(null);
        assertNotEquals(i2, i);
        i2.setDomain("sample.com");

        i2.setSignature(null);
        assertNotEquals(i2, i);
        
        i2.setDocument(null);
        assertNotEquals(i2, i);

        assertNotEquals("", i);
    }

}

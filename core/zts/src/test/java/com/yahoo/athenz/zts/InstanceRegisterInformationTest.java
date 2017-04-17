/**
 * Copyright 2017 Yahoo Inc.
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

public class InstanceRegisterInformationTest {

    @Test
    public void testInstanceRegisterInformation() {
        InstanceRegisterInformation i = new InstanceRegisterInformation();
        InstanceRegisterInformation i2 = new InstanceRegisterInformation();

        // set
        i.setAttestationData("doc");
        i.setProvider("provider");
        i.setDomain("sample.com");
        i.setService("sample.service");
        i.setCsr("sample_csr");
        i.setSsh("ssh");
        i.setToken(false);
        i2.setProvider("provider");
        i2.setAttestationData("doc");
        i2.setDomain("sample.com");
        i2.setService("sample.service");
        i2.setCsr("sample_csr");
        i2.setSsh("ssh");
        i2.setToken(false);

        // getter assertion
        assertEquals(i.getAttestationData(), "doc");
        assertEquals(i.getDomain(), "sample.com");
        assertEquals(i.getService(), "sample.service");
        assertEquals(i.getCsr(), "sample_csr");
        assertEquals(i.getProvider(), "provider");
        assertEquals(i.getSsh(), "ssh");
        assertEquals(i.getToken(), Boolean.FALSE);
        
        assertTrue(i.equals(i2));
        
        i2.setService(null);
        assertFalse(i2.equals(i));
        i2.setService("sample.service");

        i2.setDomain(null);
        assertFalse(i2.equals(i));
        i2.setDomain("sample.com");

        i2.setProvider(null);
        assertFalse(i2.equals(i));
        i2.setProvider("provider");

        i2.setAttestationData(null);
        assertFalse(i2.equals(i));
    }
}

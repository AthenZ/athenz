/*
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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

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
        i.setExpiryTime(180);
        i.setHostname("host1.athenz.cloud");

        i2.setProvider("provider");
        i2.setAttestationData("doc");
        i2.setDomain("sample.com");
        i2.setService("sample.service");
        i2.setCsr("sample_csr");
        i2.setSsh("ssh");
        i2.setToken(false);
        i2.setExpiryTime(180);
        i2.setHostname("host1.athenz.cloud");

        // getter assertion
        assertEquals(i.getAttestationData(), "doc");
        assertEquals(i.getDomain(), "sample.com");
        assertEquals(i.getService(), "sample.service");
        assertEquals(i.getCsr(), "sample_csr");
        assertEquals(i.getProvider(), "provider");
        assertEquals(i.getSsh(), "ssh");
        assertEquals(i.getToken(), Boolean.FALSE);
        assertEquals(i.getExpiryTime(), Integer.valueOf(180));
        assertEquals(i.getHostname(), "host1.athenz.cloud");

        assertEquals(i2, i);
        assertTrue(i2.equals(i2));
        assertFalse(i2.equals(null));
        assertFalse(i2.equals("string"));

        i2.setService(null);
        assertNotEquals(i, i2);
        i2.setService("service2");
        assertNotEquals(i, i2);
        i2.setService("sample.service");

        i2.setDomain(null);
        assertNotEquals(i, i2);
        i2.setDomain("domain2");
        assertNotEquals(i, i2);
        i2.setDomain("sample.com");

        i2.setProvider(null);
        assertNotEquals(i, i2);
        i2.setProvider("provider2");
        assertNotEquals(i, i2);
        i2.setProvider("provider");

        i2.setAttestationData(null);
        assertNotEquals(i, i2);
        i2.setAttestationData("doc2");
        assertNotEquals(i, i2);
        i2.setAttestationData("doc");

        i2.setCsr(null);
        assertNotEquals(i, i2);
        i2.setCsr("csr2");
        assertNotEquals(i, i2);
        i2.setCsr("sample_csr");

        i2.setSsh(null);
        assertNotEquals(i, i2);
        i2.setSsh("ssh2");
        assertNotEquals(i, i2);
        i2.setSsh("ssh");

        i2.setToken(null);
        assertNotEquals(i, i2);
        i2.setToken(true);
        assertNotEquals(i, i2);
        i2.setToken(false);

        i2.setExpiryTime(null);
        assertNotEquals(i, i2);
        i2.setExpiryTime(120);
        assertNotEquals(i, i2);
        i2.setExpiryTime(180);

        i2.setHostname(null);
        assertNotEquals(i, i2);
        i2.setHostname("host2");
        assertNotEquals(i, i2);
        i2.setHostname("host1.athenz.cloud");

        assertEquals(i, i2);
    }
}

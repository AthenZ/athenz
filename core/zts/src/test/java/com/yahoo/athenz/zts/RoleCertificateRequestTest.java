/*
 * Copyright 2018 Oath Inc.
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

import org.testng.annotations.*;

import static org.testng.Assert.*;

@SuppressWarnings({"EqualsWithItself", "EqualsBetweenInconvertibleTypes"})
public class RoleCertificateRequestTest {

    @Test
    public void testRoleCertificateRequest() {

        RoleCertificateRequest data1 = new RoleCertificateRequest();
        data1.setCsr("csr1");
        data1.setProxyForPrincipal("proxy");

        RoleCertificateRequest data2 = new RoleCertificateRequest();
        data2.setCsr("csr1");
        data2.setProxyForPrincipal("proxy");

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        data2.setExpiryTime(101);

        // verify getters
        assertEquals("csr1", data2.getCsr());
        assertEquals(101, data2.getExpiryTime());
        assertEquals("proxy", data2.getProxyForPrincipal());

        assertNotEquals(data2, data1);

        data1.setExpiryTime(101);
        assertEquals(data2, data1);

        data1.setCsr("csr2");
        assertNotEquals(data2, data1);

        data1.setCsr(null);
        assertNotEquals(data2, data1);
        data1.setCsr("csr1");

        data1.setProxyForPrincipal("proxy1");
        assertNotEquals(data2, data1);

        data1.setProxyForPrincipal(null);
        assertNotEquals(data2, data1);
        data1.setProxyForPrincipal("proxy1");

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }
}

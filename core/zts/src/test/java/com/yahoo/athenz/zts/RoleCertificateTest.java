/*
 * Copyright 2019 Oath Holdings Inc.
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class RoleCertificateTest {

    @Test
    public void testRoleCertificateRequest() {

        RoleCertificate data1 = new RoleCertificate();
        data1.setX509Certificate("x509cert");

        RoleCertificate data2 = new RoleCertificate();
        data2.setX509Certificate("x509cert");

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        // verify getters
        assertEquals("x509cert", data2.getX509Certificate());

        data1.setX509Certificate("x509cert1");
        assertNotEquals(data2, data1);
        data1.setX509Certificate(null);
        assertNotEquals(data2, data1);

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }
}

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

import static org.testng.Assert.*;

import java.util.HashMap;

import org.testng.annotations.Test;

@SuppressWarnings("EqualsWithItself")
public class InstanceIdentityTest {

    @Test
    public void testInstanceIdentity() {
        InstanceIdentity i = new InstanceIdentity();
        InstanceIdentity i2 = new InstanceIdentity();

        HashMap<String, String> attr = new HashMap<String, String>() {

            private static final long serialVersionUID = 1L;

            {
                put("hosts", "sample.athenz.com");
                put("user", "user.test");
            }
        };

        // set
        i.setName("sample");
        i.setX509Certificate("sample_cert");
        i.setX509CertificateSigner("sample_certbundle");
        i.setSshCertificate("sample_sshcert");
        i.setServiceToken("sample_token");
        i2.setName("sample");
        i2.setX509Certificate("sample_cert");
        i2.setX509CertificateSigner("sample_certbundle");
        i2.setSshCertificate("sample_sshcert");
        i2.setServiceToken("sample_token");
        i.setAttributes(attr);

        // getter assertion
        assertEquals(i.getName(), "sample");
        assertEquals(i.getX509Certificate(), "sample_cert");
        assertEquals(i.getX509CertificateSigner(), "sample_certbundle");
        assertEquals(i.getSshCertificate(), "sample_sshcert");
        assertEquals(i.getServiceToken(), "sample_token");
        assertEquals(i.getAttributes(), attr);

        assertEquals(i, i);

        assertNotEquals(i2, i);
        i2.setServiceToken(null);
        assertNotEquals(i2, i);
        i2.setSshCertificate(null);
        assertNotEquals(i2, i);
        i2.setX509CertificateSigner(null);
        assertNotEquals(i2, i);
        i2.setX509CertificateSigner(null);
        assertNotEquals(i2, i);
        i2.setName(null);
        assertNotEquals(i2, i);

        //noinspection EqualsBetweenInconvertibleTypes
        assertNotEquals("", i);
    }
}

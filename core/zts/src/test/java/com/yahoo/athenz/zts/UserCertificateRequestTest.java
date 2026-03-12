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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

@SuppressWarnings("EqualsWithItself")
public class UserCertificateRequestTest {

    @Test
    public void testUserCertificateRequest() {
        UserCertificateRequest r1 = new UserCertificateRequest();
        r1.setName("user.joe");
        r1.setCsr("test_csr");
        r1.setAttestationData("attestation_data");
        r1.setExpiryTime(123456789);
        r1.setX509CertSignerKeyId("x509KeyId");

        UserCertificateRequest r2 = new UserCertificateRequest();
        r2.setName("user.joe");
        r2.setCsr("test_csr");
        r2.setAttestationData("attestation_data");
        r2.setExpiryTime(123456789);
        r2.setX509CertSignerKeyId("x509KeyId");

        // getters
        assertEquals(r1.getName(), "user.joe");
        assertEquals(r1.getCsr(), "test_csr");
        assertEquals(r1.getAttestationData(), "attestation_data");
        assertEquals(r1.getExpiryTime(), (Integer) 123456789);
        assertEquals(r1.getX509CertSignerKeyId(), "x509KeyId");

        assertEquals(r1, r1);
        assertEquals(r2, r1);

        r2.setName("user.jane");
        assertNotEquals(r1, r2);
        r2.setName(null);
        assertNotEquals(r1, r2);
        r2.setName("user.joe");

        r2.setCsr("csr2");
        assertNotEquals(r1, r2);
        r2.setCsr(null);
        assertNotEquals(r1, r2);
        r2.setCsr("test_csr");

        r2.setAttestationData("attestation_data2");
        assertNotEquals(r1, r2);
        r2.setAttestationData(null);
        assertNotEquals(r1, r2);
        r2.setAttestationData("attestation_data");

        r2.setExpiryTime(100);
        assertNotEquals(r1, r2);
        r2.setExpiryTime(null);
        assertNotEquals(r1, r2);
        r2.setExpiryTime(123456789);

        r2.setX509CertSignerKeyId("keyid");
        assertNotEquals(r1, r2);
        r2.setX509CertSignerKeyId(null);
        assertNotEquals(r1, r2);
        r2.setX509CertSignerKeyId("x509KeyId");
        assertEquals(r1, r2);

        assertNotEquals(r1, null);
        assertNotEquals("data", r1);
    }
}

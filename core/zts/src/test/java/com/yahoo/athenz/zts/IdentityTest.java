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

import static org.testng.Assert.*;

import java.util.Collections;
import java.util.HashMap;

import org.testng.annotations.Test;

public class IdentityTest {

    @Test
    public void testIdentity() {
        Identity i1 = new Identity();
        Identity i2 = new Identity();

        HashMap<String, String> attrs = new HashMap<String, String>() {

            private static final long serialVersionUID = 1L;

            {
                put("hosts", "sample.athenz.com");
                put("user", "user.test");
            }
        };

        // set
        i1.setName("sample");
        i1.setCertificate("sample_cert");
        i1.setCaCertBundle("sample_certbundle");
        i1.setSshCertificate("sample_sshcert");
        i1.setServiceToken("sample_token");
        i1.setAttributes(attrs);
        i1.setSshCertificateSigner("signer");

        i2.setName("sample");
        i2.setCertificate("sample_cert");
        i2.setCaCertBundle("sample_certbundle");
        i2.setSshCertificate("sample_sshcert");
        i2.setServiceToken("sample_token");
        i2.setAttributes(attrs);
        i2.setSshCertificateSigner("signer");

        // getter assertion
        assertEquals(i1.getName(), "sample");
        assertEquals(i1.getCertificate(), "sample_cert");
        assertEquals(i1.getCaCertBundle(), "sample_certbundle");
        assertEquals(i1.getSshCertificate(), "sample_sshcert");
        assertEquals(i1.getServiceToken(), "sample_token");
        assertEquals(i1.getAttributes(), attrs);
        assertEquals(i1.getSshCertificateSigner(), "signer");

        assertEquals(i1, i1);
        assertEquals(i2, i1);

        i2.setName("sample1");
        assertNotEquals(i1, i2);
        i2.setName(null);
        assertNotEquals(i1, i2);
        i2.setName("sample");

        i2.setCertificate("cert2");
        assertNotEquals(i1, i2);
        i2.setCertificate(null);
        assertNotEquals(i1, i2);
        i2.setCertificate("sample_cert");

        i2.setCaCertBundle("cert_bundle2");
        assertNotEquals(i1, i2);
        i2.setCaCertBundle(null);
        assertNotEquals(i1, i2);
        i2.setCaCertBundle("sample_certbundle");

        i2.setSshCertificate("ssh2");
        assertNotEquals(i1, i2);
        i2.setSshCertificate(null);
        assertNotEquals(i1, i2);
        i2.setSshCertificate("sample_sshcert");

        i2.setSshCertificateSigner("signer2");
        assertNotEquals(i1, i2);
        i2.setSshCertificateSigner(null);
        assertNotEquals(i1, i2);
        i2.setSshCertificateSigner("signer");

        i2.setServiceToken("token2");
        assertNotEquals(i1, i2);
        i2.setServiceToken(null);
        assertNotEquals(i1, i2);
        i2.setServiceToken("sample_token");

        i2.setAttributes(Collections.emptyMap());
        assertNotEquals(i1, i2);
        i2.setAttributes(null);
        assertNotEquals(i1, i2);
        i2.setAttributes(attrs);

        assertNotEquals("", i1);
    }
}

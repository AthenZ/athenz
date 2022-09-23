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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

public class InstanceIdentityTest {

    @Test
    public void testInstanceIdentity() {

        InstanceIdentity i1 = new InstanceIdentity();
        InstanceIdentity i2 = new InstanceIdentity();

        HashMap<String, String> attrs = new HashMap<>() {

            private static final long serialVersionUID = 1L;

            {
                put("hosts", "sample.athenz.com");
                put("user", "user.test");
            }
        };

        Timestamp start = Timestamp.fromCurrentTime();

        // set
        i1.setName("sample");
        i1.setX509Certificate("sample_cert");
        i1.setX509CertificateSigner("sample_certbundle");
        i1.setSshCertificate("sample_sshcert");
        i1.setServiceToken("sample_token");
        i1.setSshCertificateSigner("sample_ssh_signer");
        i1.setAttributes(attrs);
        i1.setProvider("provider");
        i1.setInstanceId("instanceid");
        i1.setAthenzJWK(new AthenzJWKConfig().setModified(start));

        i2.setName("sample");
        i2.setX509Certificate("sample_cert");
        i2.setX509CertificateSigner("sample_certbundle");
        i2.setSshCertificate("sample_sshcert");
        i2.setServiceToken("sample_token");
        i2.setSshCertificateSigner("sample_ssh_signer");
        i2.setAttributes(attrs);
        i2.setProvider("provider");
        i2.setInstanceId("instanceid");
        i2.setAthenzJWK(new AthenzJWKConfig().setModified(start));

        // getter assertion
        assertEquals(i1.getName(), "sample");
        assertEquals(i1.getX509Certificate(), "sample_cert");
        assertEquals(i1.getX509CertificateSigner(), "sample_certbundle");
        assertEquals(i1.getSshCertificate(), "sample_sshcert");
        assertEquals(i1.getServiceToken(), "sample_token");
        assertEquals(i1.getAttributes(), attrs);
        assertEquals(i1.getSshCertificateSigner(), "sample_ssh_signer");
        assertEquals(i1.getProvider(), "provider");
        assertEquals(i1.getInstanceId(), "instanceid");
        assertEquals(i1.getAthenzJWK(), new AthenzJWKConfig().setModified(start));

        assertEquals(i1, i1);
        assertEquals(i2, i1);

        i2.setName("sample1");
        assertNotEquals(i1, i2);
        i2.setName(null);
        assertNotEquals(i1, i2);
        i2.setName("sample");

        i2.setProvider("provider2");
        assertNotEquals(i1, i2);
        i2.setProvider(null);
        assertNotEquals(i1, i2);
        i2.setProvider("provider");

        i2.setInstanceId("id2");
        assertNotEquals(i1, i2);
        i2.setInstanceId(null);
        assertNotEquals(i1, i2);
        i2.setInstanceId("instanceid");

        i2.setX509Certificate("cert2");
        assertNotEquals(i1, i2);
        i2.setX509Certificate(null);
        assertNotEquals(i1, i2);
        i2.setX509Certificate("sample_cert");

        i2.setX509CertificateSigner("signer2");
        assertNotEquals(i1, i2);
        i2.setX509CertificateSigner(null);
        assertNotEquals(i1, i2);
        i2.setX509CertificateSigner("sample_certbundle");

        i2.setSshCertificate("ssh2");
        assertNotEquals(i1, i2);
        i2.setSshCertificate(null);
        assertNotEquals(i1, i2);
        i2.setSshCertificate("sample_sshcert");

        i2.setSshCertificateSigner("signer2");
        assertNotEquals(i1, i2);
        i2.setSshCertificateSigner(null);
        assertNotEquals(i1, i2);
        i2.setSshCertificateSigner("sample_ssh_signer");

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

        i2.setAthenzJWK(new AthenzJWKConfig());
        assertNotEquals(i1, i2);
        i2.setAthenzJWK(null);
        assertNotEquals(i1, i2);
        i2.setAthenzJWK(new AthenzJWKConfig().setModified(start));


        assertNotEquals("", i1);
    }
}

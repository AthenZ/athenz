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

import static org.testng.Assert.*;

import org.testng.annotations.Test;

import java.util.*;

@SuppressWarnings({"EqualsWithItself", "EqualsBetweenInconvertibleTypes"})
public class SSHCertificateTest {

    @Test
    public void testSSHCertRequestData() {

        SSHCertRequestData data1 = new SSHCertRequestData();
        data1.setPublicKey("publickey1");

        SSHCertRequestData data2 = new SSHCertRequestData();
        data2.setPublicKey("publickey1");

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        data2.setDestinations(Arrays.asList("dest1", "dest2"));
        data2.setPrincipals(Collections.singletonList("principal1"));
        data2.setSources(Collections.singletonList("src1"));
        data2.setTouchPublicKey("publickey2");

        // verify getters
        assertEquals("publickey1", data2.getPublicKey());
        assertEquals(Arrays.asList("dest1", "dest2"), data2.getDestinations());
        assertEquals(Collections.singletonList("principal1"), data2.getPrincipals());
        assertEquals(Collections.singletonList("src1"), data2.getSources());
        assertEquals("publickey2", data2.getTouchPublicKey());

        assertNotEquals(data2, data1);

        data1.setPrincipals(Collections.singletonList("principal1"));
        assertNotEquals(data2, data1);

        data1.setSources(null);
        assertNotEquals(data2, data1);

        data1.setSources(Collections.singletonList("src1a"));
        assertNotEquals(data2, data1);

        data1.setSources(Collections.singletonList("src1"));
        assertNotEquals(data2, data1);

        data1.setDestinations(null);
        assertNotEquals(data2, data1);

        data1.setDestinations(Collections.singletonList("dest1"));
        assertNotEquals(data2, data1);

        data1.setDestinations(Arrays.asList("dest1", "dest2"));
        assertNotEquals(data2, data1);

        data1.setPublicKey(null);
        assertNotEquals(data2, data1);

        data1.setPublicKey("publickey1a");
        assertNotEquals(data2, data1);

        data1.setPublicKey("publickey1");
        assertNotEquals(data2, data1);

        data1.setTouchPublicKey(null);
        assertNotEquals(data2, data1);

        data1.setTouchPublicKey("publickey2a");
        assertNotEquals(data2, data1);

        data1.setTouchPublicKey("publickey2");
        assertEquals(data2, data1);

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }

    @Test
    public void testSSHCertRequestMeta() {

        SSHCertRequestMeta meta1 = new SSHCertRequestMeta();
        SSHCertRequestMeta meta2 = new SSHCertRequestMeta();

        assertEquals(meta1, meta2);
        assertEquals(meta1, meta1);

        //setters
        meta2.setRequestor("req");
        meta2.setOrigin("origin");
        meta2.setClientInfo("info");
        meta2.setSshClientVersion("1.2");
        meta2.setCertType("user");

        //getters
        assertEquals("req", meta2.getRequestor());
        assertEquals("origin", meta2.getOrigin());
        assertEquals("info", meta2.getClientInfo());
        assertEquals("1.2", meta2.getSshClientVersion());
        assertEquals("user", meta2.getCertType());

        assertNotEquals(meta2, meta1);

        meta1.setRequestor("req2");
        assertNotEquals(meta2, meta1);

        meta1.setRequestor("req");
        assertNotEquals(meta2, meta1);

        meta1.setOrigin("origin1");
        assertNotEquals(meta2, meta1);

        meta1.setOrigin("origin");
        assertNotEquals(meta2, meta1);

        meta1.setClientInfo("info1");
        assertNotEquals(meta2, meta1);

        meta1.setClientInfo("info");
        assertNotEquals(meta2, meta1);

        meta1.setSshClientVersion("1.3");
        assertNotEquals(meta2, meta1);

        meta1.setSshClientVersion("1.2");
        assertNotEquals(meta2, meta1);

        meta1.setCertType("host");
        assertNotEquals(meta2, meta1);

        meta1.setCertType("user");
        assertEquals(meta2, meta1);

        assertEquals(meta2, meta2);

        assertNotEquals(meta2, null);
        assertNotEquals("meta2", meta1);
    }

    @Test
    public void testSSHCertRequest() {

        SSHCertRequest req1 = new SSHCertRequest();
        SSHCertRequest req2 = new SSHCertRequest();

        assertEquals(req1, req2);
        assertEquals(req1, req1);

        SSHCertRequestMeta meta1 = new SSHCertRequestMeta();
        SSHCertRequestMeta meta2 = new SSHCertRequestMeta();

        meta1.setRequestor("req1");
        meta2.setRequestor("req2");

        SSHCertRequestData data1 = new SSHCertRequestData();
        SSHCertRequestData data2 = new SSHCertRequestData();

        data1.setPublicKey("publickey1");
        data2.setPublicKey("publickey2");

        req1.setCsr("csr1");
        assertEquals("csr1", req1.getCsr());

        req1.setCertRequestData(data1);
        assertEquals(data1, req1.getCertRequestData());

        req1.setCertRequestMeta(meta1);
        assertEquals(meta1, req1.getCertRequestMeta());

        req2.setCertRequestData(data2);
        req2.setCertRequestMeta(meta2);

        assertNotEquals(req1, req2);

        data2.setPublicKey("publickey1");
        assertNotEquals(req1, req2);

        meta2.setRequestor("req1");
        assertNotEquals(req1, req2);

        req2.setCsr("csr2");
        assertNotEquals(req1, req2);

        req2.setCsr("csr1");
        assertEquals(req1, req2);

        assertNotEquals(null, req1);
        assertNotEquals("data", req1);
    }

    @Test
    public void testSSHCertificate() {

        SSHCertificate ssh1 = new SSHCertificate();
        SSHCertificate ssh2 = new SSHCertificate();

        assertEquals(ssh1, ssh2);
        assertEquals(ssh2, ssh1);

        //setters
        ssh2.setPrivateKey("privatekey");
        ssh2.setPublicKey("publickey");
        ssh2.setCertificate("cert");

        //getters
        assertEquals("privatekey", ssh2.getPrivateKey());
        assertEquals("publickey", ssh2.getPublicKey());
        assertEquals("cert", ssh2.getCertificate());

        assertNotEquals(ssh2, ssh1);

        ssh1.setCertificate("cert1");
        assertNotEquals(ssh2, ssh1);

        ssh1.setCertificate("cert");
        assertNotEquals(ssh2, ssh1);

        ssh1.setPublicKey("publickey1");
        assertNotEquals(ssh2, ssh1);

        ssh1.setPublicKey("publickey");
        assertNotEquals(ssh2, ssh1);

        ssh1.setPrivateKey("privatekey1");
        assertNotEquals(ssh2, ssh1);

        ssh1.setPrivateKey("privatekey");
        assertEquals(ssh2, ssh1);

        assertEquals(ssh2, ssh2);

        assertNotEquals(ssh2, null);
        assertNotEquals("ssh2", ssh1);
    }

    @Test
    public void testSSHCertificates() {

        SSHCertificates certs1 = new SSHCertificates();
        SSHCertificates certs2 = new SSHCertificates();

        assertEquals(certs1, certs2);
        assertEquals(certs1, certs1);

        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("cert");

        certs1.setCertificates(Collections.singletonList(cert));
        assertEquals(Collections.singletonList(cert), certs1.getCertificates());

        assertNotEquals(certs1, certs2);

        certs2.setCertificates(Collections.singletonList(cert));
        assertEquals(certs1, certs2);

        certs2.setCertificateSigner("signer");
        assertNotEquals(certs1, certs2);

        assertEquals("signer", certs2.getCertificateSigner());

        certs1.setCertificateSigner("signer2");
        assertNotEquals(certs1, certs2);

        certs1.setCertificateSigner("signer");
        assertEquals(certs1, certs2);

        assertNotEquals(certs2, null);
        assertNotEquals("certs", certs1);
    }
}

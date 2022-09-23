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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.*;

public class SSHCertificateTest {

    @Test
    public void testSSHCertRequestData() {

        SSHCertRequestData data1 = new SSHCertRequestData();
        data1.setPublicKey("publickey1");
        data1.setDestinations(Arrays.asList("dest1", "dest2"));
        data1.setPrincipals(Collections.singletonList("principal1"));
        data1.setSources(Collections.singletonList("src1"));
        data1.setTouchPublicKey("publickey2");
        data1.setCaPubKeyAlgo(3);
        data1.setCommand("command");

        SSHCertRequestData data2 = new SSHCertRequestData();
        data2.setPublicKey("publickey1");
        data2.setDestinations(Arrays.asList("dest1", "dest2"));
        data2.setPrincipals(Collections.singletonList("principal1"));
        data2.setSources(Collections.singletonList("src1"));
        data2.setTouchPublicKey("publickey2");
        data2.setCaPubKeyAlgo(3);
        data2.setCommand("command");

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        // verify getters
        assertEquals("publickey1", data2.getPublicKey());
        assertEquals(Arrays.asList("dest1", "dest2"), data2.getDestinations());
        assertEquals(Collections.singletonList("principal1"), data2.getPrincipals());
        assertEquals(Collections.singletonList("src1"), data2.getSources());
        assertEquals("publickey2", data2.getTouchPublicKey());
        assertEquals(data2.getCaPubKeyAlgo().intValue(), 3);
        assertEquals(data2.getCommand(), "command");

        data1.setPrincipals(Collections.singletonList("principal2"));
        assertNotEquals(data2, data1);
        data1.setPrincipals(null);
        assertNotEquals(data2, data1);
        data1.setPrincipals(Collections.singletonList("principal1"));
        assertEquals(data2, data1);

        data1.setSources(Collections.singletonList("src1a"));
        assertNotEquals(data2, data1);
        data1.setSources(null);
        assertNotEquals(data2, data1);
        data1.setSources(Collections.singletonList("src1"));
        assertEquals(data2, data1);

        data1.setDestinations(Collections.singletonList("dest1"));
        assertNotEquals(data2, data1);
        data1.setDestinations(null);
        assertNotEquals(data2, data1);
        data1.setDestinations(Arrays.asList("dest1", "dest2"));
        assertEquals(data2, data1);

        data1.setPublicKey("publickey1a");
        assertNotEquals(data2, data1);
        data1.setPublicKey(null);
        assertNotEquals(data2, data1);
        data1.setPublicKey("publickey1");
        assertEquals(data2, data1);

        data1.setTouchPublicKey("publickey2a");
        assertNotEquals(data2, data1);
        data1.setTouchPublicKey(null);
        assertNotEquals(data2, data1);
        data1.setTouchPublicKey("publickey2");
        assertEquals(data2, data1);

        data1.setCommand("command1");
        assertNotEquals(data2, data1);
        data1.setCommand(null);
        assertNotEquals(data2, data1);
        data1.setCommand("command");
        assertEquals(data2, data1);

        data1.setCaPubKeyAlgo(2);
        assertNotEquals(data2, data1);
        data1.setCaPubKeyAlgo(null);
        assertNotEquals(data2, data1);
        data1.setCaPubKeyAlgo(3);
        assertEquals(data2, data1);

        assertNotEquals(null, data2);
        assertNotEquals("data1", data1);
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
        meta2.setAthenzService("athenz.api");
        meta2.setInstanceId("id");
        meta2.setPrevCertValidFrom(Timestamp.fromMillis(100));
        meta2.setPrevCertValidTo(Timestamp.fromMillis(200));
        meta2.setTransId("id1");
        meta2.setKeyIdPrincipals(Collections.singletonList("principal1"));

        //getters
        assertEquals("req", meta2.getRequestor());
        assertEquals("origin", meta2.getOrigin());
        assertEquals("info", meta2.getClientInfo());
        assertEquals("1.2", meta2.getSshClientVersion());
        assertEquals("user", meta2.getCertType());
        assertEquals("id", meta2.getInstanceId());
        assertEquals("athenz.api", meta2.getAthenzService());
        assertEquals(Timestamp.fromMillis(100), meta2.getPrevCertValidFrom());
        assertEquals(Timestamp.fromMillis(200), meta2.getPrevCertValidTo());
        assertEquals("id1", meta2.getTransId());
        assertEquals(Collections.singletonList("principal1"), meta2.getKeyIdPrincipals());

        assertNotEquals(meta2, meta1);

        //setters
        meta1.setRequestor("req");
        meta1.setOrigin("origin");
        meta1.setClientInfo("info");
        meta1.setSshClientVersion("1.2");
        meta1.setCertType("user");
        meta1.setAthenzService("athenz.api");
        meta1.setInstanceId("id");
        meta1.setPrevCertValidFrom(Timestamp.fromMillis(100));
        meta1.setPrevCertValidTo(Timestamp.fromMillis(200));
        meta1.setTransId("id1");
        meta1.setKeyIdPrincipals(Collections.singletonList("principal1"));

        assertEquals(meta1, meta2);

        // now process each attribute and verify matching

        meta1.setTransId("id2");
        assertNotEquals(meta2, meta1);
        meta1.setTransId(null);
        assertNotEquals(meta2, meta1);
        meta1.setTransId("id1");
        assertEquals(meta2, meta1);

        meta1.setKeyIdPrincipals(Collections.singletonList("principal2"));
        assertNotEquals(meta2, meta1);
        meta1.setKeyIdPrincipals(null);
        assertNotEquals(meta2, meta1);
        meta1.setKeyIdPrincipals(Collections.singletonList("principal1"));
        assertEquals(meta2, meta1);

        meta1.setRequestor("req2");
        assertNotEquals(meta2, meta1);
        meta1.setRequestor(null);
        assertNotEquals(meta2, meta1);
        meta1.setRequestor("req");
        assertEquals(meta2, meta1);

        meta1.setOrigin("origin1");
        assertNotEquals(meta2, meta1);
        meta1.setOrigin(null);
        assertNotEquals(meta2, meta1);
        meta1.setOrigin("origin");
        assertEquals(meta2, meta1);

        meta1.setClientInfo("info1");
        assertNotEquals(meta2, meta1);
        meta1.setClientInfo(null);
        assertNotEquals(meta2, meta1);
        meta1.setClientInfo("info");
        assertEquals(meta2, meta1);

        meta1.setSshClientVersion("1.3");
        assertNotEquals(meta2, meta1);
        meta1.setSshClientVersion(null);
        assertNotEquals(meta2, meta1);
        meta1.setSshClientVersion("1.2");
        assertEquals(meta2, meta1);

        meta1.setCertType("host");
        assertNotEquals(meta2, meta1);
        meta1.setCertType(null);
        assertNotEquals(meta2, meta1);
        meta1.setCertType("user");
        assertEquals(meta2, meta1);

        meta1.setRequestor("req2");
        assertNotEquals(meta2, meta1);
        meta1.setRequestor(null);
        assertNotEquals(meta2, meta1);
        meta1.setRequestor("req");
        assertEquals(meta2, meta1);

        meta1.setAthenzService("athenz.api2");
        assertNotEquals(meta2, meta1);
        meta1.setAthenzService(null);
        assertNotEquals(meta2, meta1);
        meta1.setAthenzService("athenz.api");
        assertEquals(meta2, meta1);

        meta1.setInstanceId("id2");
        assertNotEquals(meta2, meta1);
        meta1.setInstanceId(null);
        assertNotEquals(meta2, meta1);
        meta1.setInstanceId("id");
        assertEquals(meta2, meta1);

        meta1.setPrevCertValidFrom(Timestamp.fromMillis(1001));
        assertNotEquals(meta2, meta1);
        meta1.setPrevCertValidFrom(null);
        assertNotEquals(meta2, meta1);
        meta1.setPrevCertValidFrom(Timestamp.fromMillis(100));
        assertEquals(meta2, meta1);

        meta1.setPrevCertValidTo(Timestamp.fromMillis(1001));
        assertNotEquals(meta2, meta1);
        meta1.setPrevCertValidTo(null);
        assertNotEquals(meta2, meta1);
        meta1.setPrevCertValidTo(Timestamp.fromMillis(200));
        assertEquals(meta2, meta1);

        assertNotEquals(meta2, null);
        assertNotEquals("meta2", meta1);
    }

    @Test
    public void testSSHCertRequest() {

        SSHCertRequest req1 = new SSHCertRequest();
        SSHCertRequest req2 = new SSHCertRequest();

        req1.setCertRequestData(new SSHCertRequestData());
        req1.setCertRequestMeta(new SSHCertRequestMeta());
        req1.setCsr("csr");
        req1.setAttestationData("data");

        req2.setCertRequestData(new SSHCertRequestData());
        req2.setCertRequestMeta(new SSHCertRequestMeta());
        req2.setCsr("csr");
        req2.setAttestationData("data");

        assertEquals(req1.getCertRequestData(), new SSHCertRequestData());
        assertEquals(req1.getCertRequestMeta(), new SSHCertRequestMeta());
        assertEquals(req1.getCsr(), "csr");
        assertEquals(req1.getAttestationData(), "data");

        assertEquals(req1, req2);
        assertEquals(req1, req1);

        req1.setAttestationData("data2");
        assertNotEquals(req2, req1);
        req1.setAttestationData(null);
        assertNotEquals(req2, req1);
        req1.setAttestationData("data");
        assertEquals(req2, req1);

        req1.setCsr("csr2");
        assertNotEquals(req2, req1);
        req1.setCsr(null);
        assertNotEquals(req2, req1);
        req1.setCsr("csr");
        assertEquals(req2, req1);

        req1.setCertRequestData(new SSHCertRequestData().setCommand("command"));
        assertNotEquals(req2, req1);
        req1.setCertRequestData(null);
        assertNotEquals(req2, req1);
        req1.setCertRequestData(new SSHCertRequestData());
        assertEquals(req2, req1);

        req1.setCertRequestMeta(new SSHCertRequestMeta().setCertType("host"));
        assertNotEquals(req2, req1);
        req1.setCertRequestMeta(null);
        assertNotEquals(req2, req1);
        req1.setCertRequestMeta(new SSHCertRequestMeta());
        assertEquals(req2, req1);

        assertNotEquals(null, req2);
        assertNotEquals("req1", req1);
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

        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("cert");

        certs1.setCertificates(Collections.singletonList(cert));
        certs1.setCertificateSigner("signer");

        certs2.setCertificates(Collections.singletonList(cert));
        certs2.setCertificateSigner("signer");

        assertEquals(certs1, certs2);
        assertEquals(certs1, certs1);

        assertEquals(Collections.singletonList(cert), certs1.getCertificates());
        assertEquals(certs1.getCertificateSigner(), "signer");

        certs1.setCertificateSigner("signer1");
        assertNotEquals(certs2, certs1);
        certs1.setCertificateSigner(null);
        assertNotEquals(certs2, certs1);
        certs1.setCertificateSigner("signer");
        assertEquals(certs2, certs1);

        certs1.setCertificates(Collections.emptyList());
        assertNotEquals(certs2, certs1);
        certs1.setCertificates(null);
        assertNotEquals(certs2, certs1);
        certs1.setCertificates(Collections.singletonList(cert));
        assertEquals(certs2, certs1);

        assertNotEquals(certs2, null);
        assertNotEquals("certs", certs1);
    }
}

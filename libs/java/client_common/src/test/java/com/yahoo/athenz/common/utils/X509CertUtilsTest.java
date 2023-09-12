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
package com.yahoo.athenz.common.utils;

import static org.testng.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;

public class X509CertUtilsTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertUtilsTest.class);

    @Test
    public void testEmptyConstructor() {
        X509CertUtils certUtils = new X509CertUtils();
        assertNotNull(certUtils);
    }

    @Test
    public void testExtractHostname() throws IOException {
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        assertEquals(X509CertUtils.extractHostname(cert), "abc.athenz.com");

        // Ensure null cert argument will result in "" return value
        assertEquals(X509CertUtils.extractHostname(null), "");

        path = Paths.get("src/test/resources/athenz_no_hostname.cert.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);
        assertEquals(X509CertUtils.extractHostname(cert), "");
    }

    @Test
    public void testExtractProvider() throws IOException {
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        assertEquals(X509CertUtils.extractProvider(cert), "openstack.provider");

        // Ensure null cert argument will result in "" return value
        assertEquals(X509CertUtils.extractProvider(null), "");

        path = Paths.get("src/test/resources/athenz_no_provider.cert.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);
        assertEquals(X509CertUtils.extractProvider(cert), "");

        path = Paths.get("src/test/resources/athenz_unknown_uri.cert.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);
        assertEquals(X509CertUtils.extractProvider(cert), "");

        path = Paths.get("src/test/resources/athenz_bad_instanceid.cert.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);
        assertEquals(X509CertUtils.extractProvider(cert), "");
    }

    @Test
    public void testExtractRequestInstanceId() throws CertificateParsingException {


        assertNull(X509CertUtils.extractRequestInstanceId(null));

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Collection<List<?>> dnsNames = new ArrayList<>();
        ArrayList<Object> item1 = new ArrayList<>();
        item1.add(2);
        item1.add("host1.domain.athenz");
        dnsNames.add(item1);
        Mockito.when(cert.getSubjectAlternativeNames()).thenReturn(dnsNames);

        assertNull(X509CertUtils.extractRequestInstanceId(cert));

        ArrayList<Object> item2 = new ArrayList<>();
        item2.add(2);
        item2.add("instanceid1.instanceid.athenz.test");
        dnsNames.add(item2);

        assertEquals("instanceid1", X509CertUtils.extractRequestInstanceId(cert));
    }

    @Test
    public void textExtractRequestInstanceIdURI() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.uri.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        assertEquals("id-001", X509CertUtils.extractRequestInstanceId(cert));
    }

    @Test
    public void testLogRecord() {

        File file = new File("src/test/resources/cert_log.pem");
        String pem = null;
        try {
            pem = new String(Files.readAllBytes(file.toPath()));
        } catch (IOException ex) {
            fail();
        }
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        Principal principal = SimplePrincipal.create("user", "joe", "creds");
        String logLine = X509CertUtils.logRecord(principal, "10.11.12.13", "athenz.provider",
                "instance-id-1234", cert);
        assertEquals(logLine, "10.11.12.13 user.joe athenz.provider \"instance-id-1234\" \"CN=athenz.api,O=Athenz,ST=CA,C=US\" \"CN=AthenzTestCA,O=AthenzTest,ST=CA,C=US\" 11380750808733699965 1629005177000");

        logLine = X509CertUtils.logRecord(null, "10.11.12.13", "athenz.provider", null, cert);
        assertEquals(logLine, "10.11.12.13 - athenz.provider - \"CN=athenz.api,O=Athenz,ST=CA,C=US\" \"CN=AthenzTestCA,O=AthenzTest,ST=CA,C=US\" 11380750808733699965 1629005177000");
    }

    @Test
    public void testCertSshLogger() {

        // we should not get any exceptions when calling this log
        // record with all nulls since nothing will be processed
        // when logger is null

        X509CertUtils.logCert(null, null, null, null, null, null);
        X509CertUtils.logSSH(null, null, null, null, null);

        // we should get a null pointer exception when passing null
        // for our certificate but the log method will catch
        // all exceptions and the test will pass without any errors

        X509CertUtils.logCert(LOGGER, null, "10.11.12.13", "athenz.api", "id1234", null);
        X509CertUtils.logSSH(LOGGER, null, "10.11.12.13", "athenz.api", "id1234");

        // now let's pass with valid cert

        File file = new File("src/test/resources/cert_log.pem");
        String pem = null;
        try {
            pem = new String(Files.readAllBytes(file.toPath()));
        } catch (IOException ex) {
            fail();
        }
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        Principal principal = SimplePrincipal.create("user", "joe", "creds");
        X509CertUtils.logCert(LOGGER, principal, "10.11.12.13", "athenz.provider", "instance-id-1234", cert);
    }

    @Test
    public void testExtractReqeustInstanceIdFromURI() {

        // first no list

        List<String> uriList = new ArrayList<>();
        assertNull(X509CertUtils.extractRequestInstanceIdFromURI(uriList));

        // does not start with uri

        uriList.add("spiffe://athenz/sa/api");
        assertNull(X509CertUtils.extractRequestInstanceIdFromURI(uriList));

        // does not have correct format

        uriList.add("athenz://instanceid/provider-id-001");
        assertNull(X509CertUtils.extractRequestInstanceIdFromURI(uriList));

        // finally correct format

        uriList.add("athenz://instanceid/provider/id-001");
        assertEquals(X509CertUtils.extractRequestInstanceIdFromURI(uriList), "id-001");
    }

    @Test
    public void testExtractItemFromURI() {

        // first no list

        List<String> uriList = new ArrayList<>();
        assertNull(X509CertUtils.extractItemFromURI(uriList, "athenz://"));

        // does not start with uri

        uriList.add("spiffe://athenz/sa/api");
        assertNull(X509CertUtils.extractItemFromURI(uriList, "athenz://"));

        // finally correct match

        uriList.add("athenz://instanceid/provider/id-001");
        assertEquals(X509CertUtils.extractItemFromURI(uriList, "athenz://"), "instanceid/provider/id-001");
    }

    @Test
    public void testHexKeyMod() {
        assertEquals(X509CertUtils.hexKeyMod(null, false), "");
        assertEquals(X509CertUtils.hexKeyMod(new X509Certificate[]{}, false), "");

        // RSA cert
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        assertEquals(X509CertUtils.hexKeyMod(certs, true), "56aa8697b9720f9b17e2ba612c60d20572a3344178a7faf7a53e9cc55b3f85ef");
        assertEquals(X509CertUtils.hexKeyMod(certs, false), "164dca6cd0987c738eb434037bd9bf107e0cd5b649cf62dd66596f54cf277ad0");

        // EC cert
        certs = new X509Certificate[]{Crypto.loadX509Certificate(Paths.get("src/test/resources/athenz.ec.cert.pem").toFile())};
        assertEquals(X509CertUtils.hexKeyMod(certs, true), "");
    }

    @Test
    public void testExtractKeyModulus() {
        assertEquals(X509CertUtils.extractKeyModulus((X509Certificate[]) null), "");
        assertEquals(X509CertUtils.extractKeyModulus(new X509Certificate[]{}), "");

        // RSA cert
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        assertEquals(X509CertUtils.extractKeyModulus(certs), "c4f9de698e008aba0930d4fff2fdd462aab4fbfb16572785cb8b8ac98a8979c8e9ff5a18c0642818aa4f1e5290306196e4dd1951a5b82f7ec2dc664d7472cc823823c6bf521e2ad6238fa0fe2e50e2ed16211d553f5678cee0effd5b36ce0e8d42f76ed8f4eab11d8db8b520ea20c55c92318f3ef2246c9382220ce9c82de94b1217a3a83a1a7584c62c305609fb3fa4831bfb13030d987822725954bcbc81a58981c75172e0f0bbda702eae8bf90c92444319d679974a349742dfa77920f5d476ea032b8dbf54ed4283ab320e4677369b367e444ae9451d09c38d6366730379545e7795c5724c91bf95c65c974ca711d4feb39c0fc258d68b467c7d705f8221");

        // EC cert
        certs = new X509Certificate[]{Crypto.loadX509Certificate(Paths.get("src/test/resources/athenz.ec.cert.pem").toFile())};
        assertEquals(X509CertUtils.extractKeyModulus(certs), "");
    }

    @Test
    public void testExtractCn() {
        assertEquals(X509CertUtils.extractCn((X509Certificate[]) null), "");
        assertEquals(X509CertUtils.extractCn(new X509Certificate[]{}), "");

        // RSA cert
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        assertEquals(X509CertUtils.extractCn(certs), "athenz.examples.httpd");
    }

    @Test
    public void testExtractIssuerCn() {
        assertEquals(X509CertUtils.extractIssuerCn((X509Certificate[]) null), "");
        assertEquals(X509CertUtils.extractIssuerCn(new X509Certificate[]{}), "");

        // RSA cert
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        assertEquals(X509CertUtils.extractIssuerCn(certs), "self.signer.root");
    }

    @Test
    public void testExtractIssuerDn() {
        assertEquals(X509CertUtils.extractIssuerDn((X509Certificate[]) null), "");
        assertEquals(X509CertUtils.extractIssuerDn(new X509Certificate[]{}), "");

        // RSA cert
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        assertEquals(X509CertUtils.extractIssuerDn(certs), "CN=self.signer.root");
    }

    @Test
    public void testExtractSubjectDn() {
        assertEquals(X509CertUtils.extractSubjectDn((X509Certificate[]) null), "");
        assertEquals(X509CertUtils.extractSubjectDn(new X509Certificate[]{}), "");

        // RSA cert
        Path path = Paths.get("src/test/resources/athenz_hostname.cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        assertEquals(X509CertUtils.extractSubjectDn(certs), "CN=athenz.examples.httpd,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US");
    }

    @Test
    public void testTestExtractIssuerDn() {
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            System.out.println(X509CertUtils.extractIssuerDn(cert));
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
    }
}

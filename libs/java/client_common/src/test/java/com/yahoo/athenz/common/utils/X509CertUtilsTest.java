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
package com.yahoo.athenz.common.utils;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
}

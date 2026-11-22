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

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.identity.SelfIdentityStore;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class SelfIdentityManagerTest {

    private PrivateKey caKey;
    private X509Certificate caCert;
    private String caPem;

    @BeforeClass
    public void setupCA() throws Exception {
        caKey = Crypto.generateRSAPrivateKey(2048);
        final String caCsr = Crypto.generateX509CSR(caKey, "cn=Self Identity Test CA", null);
        caCert = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(caCsr), caKey,
                new X500Name("cn=Self Identity Test CA"), 60, true);
        caPem = Crypto.convertToPEMFormat(caCert);
    }

    @AfterMethod(alwaysRun = true)
    public void cleanup() {
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_CERT_EXPIRY_MINS);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_KEY_ALGORITHM);
        System.clearProperty(ZTSConsts.ZTS_PROP_SPIFFE_TRUST_DOMAIN);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_REFRESH_INTERVAL_MINS);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT);
    }

    // records the requests and signs them with the test ca like our server would
    private class TestIssuer implements SelfIdentityManager.CertIssuer {

        String csr;
        int expiryMins = -1;
        boolean includeChain = false;
        String caBundle = null;

        @Override
        public Identity issue(String domainName, String serviceName, String csr, int expiryMins) {
            assertEquals(domainName, "sys.auth");
            assertEquals(serviceName, "zts");
            this.csr = csr;
            this.expiryMins = expiryMins;
            X509Certificate cert = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr),
                    caKey, caCert, 1440, false);
            final String pem = Crypto.convertToPEMFormat(cert);
            return new Identity().setCertificate(includeChain ? pem + caPem : pem).setCaCertBundle(caBundle);
        }
    }


    @SuppressWarnings("unchecked")
    private List<X509Certificate> capturedCertChain(SelfIdentityStore store) throws ServerResourceException {
        ArgumentCaptor<List<X509Certificate>> captor = ArgumentCaptor.forClass(List.class);
        Mockito.verify(store, Mockito.atLeastOnce()).storeIdentity(any(), captor.capture(), any());
        return captor.getValue();
    }

    @SuppressWarnings("unchecked")
    private List<X509Certificate> capturedCaCerts(SelfIdentityStore store) throws ServerResourceException {
        ArgumentCaptor<List<X509Certificate>> captor = ArgumentCaptor.forClass(List.class);
        Mockito.verify(store, Mockito.atLeastOnce()).storeIdentity(any(), any(), captor.capture());
        return captor.getValue();
    }

    @Test
    public void testStartIssuesAndStoresIdentity() throws Exception {

        SelfIdentityStore store = Mockito.mock(SelfIdentityStore.class);
        TestIssuer issuer = new TestIssuer();
        issuer.caBundle = caPem;

        SelfIdentityManager manager = new SelfIdentityManager(store, issuer);
        manager.start();
        try {
            ArgumentCaptor<PrivateKey> keyCaptor = ArgumentCaptor.forClass(PrivateKey.class);
            Mockito.verify(store).storeIdentity(keyCaptor.capture(), any(), any());
            final List<X509Certificate> certChain = capturedCertChain(store);

            // the csr carries our service identity and the requested expiry is the server default

            PKCS10CertificationRequest csr = Crypto.getPKCS10CertRequest(issuer.csr);
            assertEquals(Crypto.extractX509CSRCommonName(csr), "sys.auth.zts");
            assertEquals(Crypto.extractX509CSRURIs(csr), List.of("spiffe://athenz.io/ns/default/sa/sys.auth.zts"));
            assertEquals(issuer.expiryMins, 0);

            assertEquals(keyCaptor.getValue().getAlgorithm(), "RSA");
            assertEquals(certChain.size(), 1);
            assertEquals(Crypto.extractPublicKey(keyCaptor.getValue()).getEncoded(),
                    certChain.get(0).getPublicKey().getEncoded());

            // the ca bundle is passed separately

            assertEquals(capturedCaCerts(store), List.of(caCert));
            assertNotNull(manager.scheduler);
        } finally {
            manager.close();
        }
        assertTrue(manager.scheduler.isShutdown());
    }

    @Test
    public void testIssueWithChainEcKeyAndConfiguredExpiry() throws Exception {

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_KEY_ALGORITHM, "ec");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_CERT_EXPIRY_MINS, "360");
        System.setProperty(ZTSConsts.ZTS_PROP_SPIFFE_TRUST_DOMAIN, "athenz.example");

        SelfIdentityStore store = Mockito.mock(SelfIdentityStore.class);
        TestIssuer issuer = new TestIssuer();
        issuer.includeChain = true;
        issuer.caBundle = caPem;

        SelfIdentityManager manager = new SelfIdentityManager(store, issuer);
        X509Certificate cert = manager.refreshIdentity();

        assertEquals(issuer.expiryMins, 360);
        assertEquals(Crypto.extractX509CSRURIs(Crypto.getPKCS10CertRequest(issuer.csr)),
                List.of("spiffe://athenz.example/ns/default/sa/sys.auth.zts"));
        ArgumentCaptor<PrivateKey> keyCaptor = ArgumentCaptor.forClass(PrivateKey.class);
        Mockito.verify(store).storeIdentity(keyCaptor.capture(), any(), any());
        assertEquals(keyCaptor.getValue().getAlgorithm(), "EC");

        // the certificate is passed as returned by the signer, with the
        // intermediate following the leaf certificate

        assertEquals(capturedCertChain(store), List.of(cert, caCert));
        assertEquals(capturedCaCerts(store), List.of(caCert));
    }

    @Test
    public void testIssueWithoutCaCerts() throws Exception {

        SelfIdentityStore store = Mockito.mock(SelfIdentityStore.class);
        TestIssuer issuer = new TestIssuer();

        SelfIdentityManager manager = new SelfIdentityManager(store, issuer);
        manager.refreshIdentity();
        assertEquals(capturedCaCerts(store), Collections.emptyList());

        issuer.caBundle = "";
        manager.refreshIdentity();
        assertEquals(capturedCaCerts(store), Collections.emptyList());
    }

    @Test
    public void testSpiffeUriFormat() throws Exception {

        SelfIdentityStore store = Mockito.mock(SelfIdentityStore.class);

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT, "Basic");
        assertEquals(new SelfIdentityManager(store, new TestIssuer()).spiffeUri, "spiffe://sys.auth/sa/zts");

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT, "trust_domain");
        assertEquals(new SelfIdentityManager(store, new TestIssuer()).spiffeUri,
                "spiffe://athenz.io/ns/default/sa/sys.auth.zts");

        // no spiffe uri is included in the request

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT, "none");
        TestIssuer issuer = new TestIssuer();
        SelfIdentityManager manager = new SelfIdentityManager(store, issuer);
        assertNull(manager.spiffeUri);
        manager.refreshIdentity();
        assertTrue(Crypto.extractX509CSRURIs(Crypto.getPKCS10CertRequest(issuer.csr)).isEmpty());

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_SPIFFE_URI_FORMAT, "unknown");
        ServerResourceException ex = expectThrows(ServerResourceException.class,
                () -> new SelfIdentityManager(store, new TestIssuer()));
        assertTrue(ex.getMessage().contains("unsupported"));
    }

    @Test
    public void testInvalidKeyAlgorithm() {
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_KEY_ALGORITHM, "DSA");
        ServerResourceException ex = expectThrows(ServerResourceException.class,
                () -> new SelfIdentityManager(Mockito.mock(SelfIdentityStore.class), new TestIssuer()));
        assertTrue(ex.getMessage().contains("unsupported"));
    }

    @Test
    public void testIssueFailures() throws Exception {

        SelfIdentityStore store = Mockito.mock(SelfIdentityStore.class);

        // the request rejected by the server is reported as is

        SelfIdentityManager manager = new SelfIdentityManager(store, (domain, service, csr, expiry) -> {
            throw new ServerResourceException(ServerResourceException.BAD_REQUEST, "Invalid CSR - spiffe uri mismatch");
        });
        ServerResourceException ex = expectThrows(ServerResourceException.class, manager::start);
        assertEquals(ex.getCode(), ServerResourceException.BAD_REQUEST);
        assertTrue(ex.getMessage().contains("spiffe uri mismatch"));

        assertIssueFails(store, new Identity().setCertificate("invalid-certificate"), "unable to parse certificate");
        assertIssueFails(store, new Identity(), "unable to issue self identity certificate");

        // failure to store the identity

        Mockito.doThrow(new IllegalStateException("disk full")).when(store).storeIdentity(any(), any(), any());
        manager = new SelfIdentityManager(store, new TestIssuer());
        ex = expectThrows(ServerResourceException.class, manager::start);
        assertTrue(ex.getMessage().contains("disk full"));
        assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
    }

    @Test
    public void testValidateCertificate() throws Exception {

        SelfIdentityManager manager = new SelfIdentityManager(Mockito.mock(SelfIdentityStore.class),
                new TestIssuer());
        PrivateKey key = Crypto.generateRSAPrivateKey(2048);

        X509Certificate otherName = issue(key, "cn=sys.auth.other", 60);
        ServerResourceException ex = expectThrows(ServerResourceException.class,
                () -> manager.validateCertificate(otherName, key));
        assertTrue(ex.getMessage().contains("unexpected certificate common name"));

        X509Certificate valid = issue(key, "cn=sys.auth.zts", 60);
        PrivateKey otherKey = Crypto.generateRSAPrivateKey(2048);
        ex = expectThrows(ServerResourceException.class, () -> manager.validateCertificate(valid, otherKey));
        assertTrue(ex.getMessage().contains("does not match"));

        X509Certificate expired = issue(key, "cn=sys.auth.zts", -1);
        ex = expectThrows(ServerResourceException.class, () -> manager.validateCertificate(expired, key));
        assertTrue(ex.getMessage().contains("already expired"));

        manager.validateCertificate(valid, key);
    }

    @Test
    public void testRefreshTask() throws Exception {

        SelfIdentityStore store = Mockito.mock(SelfIdentityStore.class);
        SelfIdentityManager manager = new SelfIdentityManager(store, new TestIssuer());
        ScheduledExecutorService scheduler = Mockito.mock(ScheduledExecutorService.class);
        manager.scheduler = scheduler;

        // a successful refresh stores a new identity and schedules
        // the next one after the default refresh interval (24 hours)

        manager.refreshTask();
        final X509Certificate firstCert = capturedCertChain(store).get(0);
        ArgumentCaptor<Long> delayCaptor = ArgumentCaptor.forClass(Long.class);
        Mockito.verify(scheduler).schedule(any(Runnable.class), delayCaptor.capture(), eq(TimeUnit.MILLISECONDS));
        assertEquals(delayCaptor.getValue().longValue(), TimeUnit.MINUTES.toMillis(1440));

        manager.refreshTask();
        Mockito.verify(store, Mockito.times(2)).storeIdentity(any(), any(), any());
        assertNotEquals(capturedCertChain(store).get(0), firstCert);

        // a failed refresh retries after the retry interval

        Mockito.doThrow(new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, "disk full"))
                .when(store).storeIdentity(any(), any(), any());
        manager.refreshTask();
        Mockito.verify(scheduler).schedule(any(Runnable.class), eq(TimeUnit.MINUTES.toMillis(5)),
                eq(TimeUnit.MILLISECONDS));

        // nothing is scheduled once the scheduler has been shut down

        Mockito.when(scheduler.isShutdown()).thenReturn(true);
        manager.refreshTask();
        Mockito.verify(scheduler, Mockito.times(3)).schedule(any(Runnable.class), anyLong(), any());
    }

    @Test
    public void testRefreshInterval() throws Exception {

        // invalid values fall back to the default interval

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_REFRESH_INTERVAL_MINS, "0");
        SelfIdentityManager manager = new SelfIdentityManager(Mockito.mock(SelfIdentityStore.class),
                new TestIssuer());
        assertEquals(manager.refreshIntervalMillis, TimeUnit.MINUTES.toMillis(1440));

        // the configured interval is used as is, both when it is shorter than
        // the certificate lifetime (1440 mins) and when it is longer

        for (int intervalMins : new int[] { 60, 2880 }) {
            System.setProperty(ZTSConsts.ZTS_PROP_SELF_IDENTITY_REFRESH_INTERVAL_MINS, Integer.toString(intervalMins));
            manager = new SelfIdentityManager(Mockito.mock(SelfIdentityStore.class), new TestIssuer());
            ScheduledExecutorService scheduler = Mockito.mock(ScheduledExecutorService.class);
            manager.scheduler = scheduler;
            manager.refreshTask();
            Mockito.verify(scheduler).schedule(any(Runnable.class), eq(TimeUnit.MINUTES.toMillis(intervalMins)),
                    eq(TimeUnit.MILLISECONDS));
        }
    }

    @Test
    public void testCloseWithoutStart() throws Exception {
        new SelfIdentityManager(Mockito.mock(SelfIdentityStore.class), new TestIssuer()).close();
    }

    private X509Certificate issue(PrivateKey key, final String subject, int validityMins) throws Exception {
        final String csr = Crypto.generateX509CSR(key, subject, null);
        return Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey, caCert, validityMins, false);
    }

    private void assertIssueFails(SelfIdentityStore store, Identity identity, final String message)
            throws ServerResourceException {
        SelfIdentityManager manager = new SelfIdentityManager(store, (domain, service, csr, expiry) -> identity);
        ServerResourceException ex = expectThrows(ServerResourceException.class, manager::start);
        assertTrue(ex.getMessage().contains(message), ex.getMessage());
        assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
    }
}

/*
 * Copyright The Athenz Authors
 * Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
 */
package com.yahoo.athenz.zts.cert;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import com.yahoo.athenz.common.utils.X509CertUtils;
import com.yahoo.athenz.zts.cache.DataCache;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.testng.Assert.*;

public class X509SVIDRefreshTest {

    private String generateCsr(final String instanceId) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        GeneralName[] names = {
                new GeneralName(GeneralName.dNSName, "api.test.example.test"),
                new GeneralName(GeneralName.dNSName, instanceId + ".instanceid.athenz.example.test"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://test/sa/api")
        };
        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(), "CN=test.api", names);
    }

    private void validateRequest(X509ServiceCertRequest request, DataCache cache) {
        StringBuilder error = new StringBuilder();
        assertTrue(request.validate("test", "api", "sys.auth.zts", null, cache,
                null, null, null, null, null, true, error), error.toString());
        assertEquals(request.getUris(), Collections.singletonList("spiffe://test/sa/api"));
    }

    @Test
    public void testSPIFFESVIDRegistrationThenRefresh() throws Exception {
        SpiffeUriManager spiffeUriManager = new SpiffeUriManager();
        DataCache cache = new DataCache();
        cache.getProviderDnsSuffixCache().put("sys.auth.zts", Collections.singletonList("example.test"));

        // Registration must read the ID from the CSR, ahead of any request fallback.
        X509ServiceCertRequest registration = new X509ServiceCertRequest(
                generateCsr("instance-1"), spiffeUriManager, null, "fallback-id");
        validateRequest(registration, cache);
        assertEquals(registration.getInstanceId(), "instance-1");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair ca = generator.generateKeyPair();
        X509Certificate certificate = Crypto.generateX509Certificate(registration.getCertReq(),
                ca.getPrivate(), new X500Name("CN=Test CA"), 60, false);
        assertNotNull(certificate);
        certificate.verify(ca.getPublic());
        assertEquals(Crypto.extractX509CertURIs(certificate),
                Collections.singletonList("spiffe://test/sa/api"));
        assertEquals(X509CertUtils.extractRequestInstanceId(certificate), "instance-1");

        // Provider refresh has no x509CertInstanceId fallback and uses a new key.
        X509ServiceCertRequest refresh = new X509ServiceCertRequest(
                generateCsr("instance-1"), spiffeUriManager, null);
        validateRequest(refresh, cache);
        assertEquals(refresh.getInstanceId(), "instance-1");
        assertFalse(registration.getCertReq().getSubjectPublicKeyInfo()
                .equals(refresh.getCertReq().getSubjectPublicKeyInfo()));
        assertTrue(refresh.validateInstanceId("instance-1", certificate));
        assertFalse(refresh.validateInstanceId("another-instance", certificate));

        X509ServiceCertRequest otherInstance = new X509ServiceCertRequest(
                generateCsr("instance-2"), spiffeUriManager, null);
        validateRequest(otherInstance, cache);
        assertFalse(otherInstance.validateInstanceId("instance-1", certificate));
        assertFalse(otherInstance.validateInstanceId("instance-2", certificate));
    }
}

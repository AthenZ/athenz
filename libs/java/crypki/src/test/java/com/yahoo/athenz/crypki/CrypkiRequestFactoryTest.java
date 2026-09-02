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
package com.yahoo.athenz.crypki;

import com.yahoo.athenz.common.server.cert.Priority;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class CrypkiRequestFactoryTest {

    @Test
    public void testCreateRequest() {
        CrypkiRequestFactory factory = new CrypkiRequestFactory("x509-key",
                Map.of("athenz.aws.us-east-1", "x509-aws-key"), 120);
        X509SignRequest request = factory.create("athenz.aws.us-east-1", "csr",
                CrypkiConsts.CERT_USAGE_CLIENT, 30, Priority.High, null);
        assertEquals(request.getKeyId(), "x509-aws-key");
        assertEquals(request.getCsrPem(), "csr");
        assertEquals(request.getValiditySeconds(), 1800);
        assertEquals(request.getExtKeyUsage(), List.of(2));
        assertEquals(request.getPriority(), Priority.High);
    }

    @Test
    public void testResolveKeyId() {
        CrypkiRequestFactory factory = new CrypkiRequestFactory("x509-key",
                Map.of("p1", "k1"), 43200);
        assertEquals(factory.resolveKeyId("p1", null), "k1");
        assertEquals(factory.resolveKeyId("p1", "explicit"), "explicit");
        assertEquals(factory.resolveKeyId("unknown", ""), "x509-key");
        assertEquals(factory.resolveKeyId(null, null), "x509-key");
        assertEquals(new CrypkiRequestFactory().resolveKeyId("x", null), "x509-key");
        assertEquals(new CrypkiRequestFactory("", Map.of(), 60).resolveKeyId(null, null),
                CrypkiConsts.DEFAULT_KEY_ID);
        expectThrows(NullPointerException.class, () -> X509SignRequest.builder().build());
        assertEquals(X509SignRequest.builder().csrPem("csr").build().getPriority(),
                Priority.Unspecified_priority);
        assertTrue(X509SignRequest.builder().csrPem("csr").build().getExtKeyUsage().isEmpty());
    }

    @Test
    public void testForKmsUsesConfiguredKeyId() {
        System.setProperty(CrypkiConsts.PROP_KMS_KEY_ID, "alias/example-ca");
        try {
            CrypkiRequestFactory factory = CrypkiRequestFactory.forKms();
            assertEquals(factory.resolveKeyId(null, null), "alias/example-ca");
            assertEquals(factory.resolveKeyId("provider", ""), "alias/example-ca");
            assertEquals(factory.resolveKeyId(null, "explicit-id"), "explicit-id");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_KMS_KEY_ID);
        }
        assertEquals(CrypkiRequestFactory.forKms().resolveKeyId(null, null), CrypkiConsts.DEFAULT_KEY_ID);
    }

    @Test
    public void testForHsmUsesConfiguredLabel() {
        System.setProperty(CrypkiConsts.PROP_HSM_KEY_LABEL, "example-hsm-label");
        try {
            CrypkiRequestFactory factory = CrypkiRequestFactory.forHsm();
            assertEquals(factory.resolveKeyId(null, null), "example-hsm-label");
            assertEquals(factory.resolveKeyId("provider", ""), "example-hsm-label");
            assertEquals(factory.resolveKeyId(null, "explicit-id"), "explicit-id");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_KEY_LABEL);
        }
        assertEquals(CrypkiRequestFactory.forHsm().resolveKeyId(null, null),
                CrypkiConsts.DEFAULT_HSM_KEY_LABEL);
    }

    @Test
    public void testExtKeyUsage() {
        assertEquals(CrypkiRequestFactory.toExtKeyUsage(CrypkiConsts.CERT_USAGE_CLIENT), List.of(2));
        assertEquals(CrypkiRequestFactory.toExtKeyUsage(CrypkiConsts.CERT_USAGE_CODE_SIGNING), List.of(3));
        assertEquals(CrypkiRequestFactory.toExtKeyUsage(CrypkiConsts.CERT_USAGE_TIMESTAMPING), List.of(8));
        assertTrue(CrypkiRequestFactory.toExtKeyUsage(null).isEmpty());
        assertTrue(CrypkiRequestFactory.toExtKeyUsage("server").isEmpty());
    }

    @Test
    public void testValidityCap() {
        CrypkiRequestFactory factory = new CrypkiRequestFactory(null, null, 0);
        assertEquals(factory.toValiditySeconds(0), 43200 * 60);
        assertEquals(factory.toValiditySeconds(999999), 43200 * 60);
    }
}

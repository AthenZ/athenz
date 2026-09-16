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
package com.yahoo.athenz.crypki.kms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class KmsCaCertificateStoreTest {

    @Test
    public void testDefaultPath() throws Exception {
        X509Certificate ca = selfSigned("CN=default-ca");
        String path = writePem(ca);
        KmsCaCertificateStore store = new KmsCaCertificateStore(path, null);
        assertEquals(store.get("alias/any").getSubjectX500Principal(), ca.getSubjectX500Principal());
        assertEquals(store.get(null).getSubjectX500Principal(), ca.getSubjectX500Principal());
        assertEquals(store.get("").getSubjectX500Principal(), ca.getSubjectX500Principal());
        assertTrue(store.getCertPathsByKeyId().isEmpty());
    }

    @Test
    public void testMapOverridesDefault() throws Exception {
        X509Certificate defaultCa = selfSigned("CN=default-ca");
        X509Certificate tenantA = selfSigned("CN=tenant-a-ca");
        X509Certificate tenantB = selfSigned("CN=tenant-b-ca");
        String defaultPath = writePem(defaultCa);
        String tenantAPath = writePem(tenantA);
        String tenantBPath = writePem(tenantB);
        String mapPath = writeMap("{\n"
                + "  \"alias/tenant-a-ca\": \"" + jsonPath(tenantAPath) + "\",\n"
                + "  \"alias/tenant-b-ca\": \"" + jsonPath(tenantBPath) + "\"\n"
                + "}\n");

        KmsCaCertificateStore store = new KmsCaCertificateStore(defaultPath, mapPath);
        assertEquals(store.get("alias/tenant-a-ca").getSubjectX500Principal(),
                tenantA.getSubjectX500Principal());
        assertEquals(store.get("alias/tenant-b-ca").getSubjectX500Principal(),
                tenantB.getSubjectX500Principal());
        assertEquals(store.get("alias/unknown").getSubjectX500Principal(),
                defaultCa.getSubjectX500Principal());
        assertEquals(store.getCertPathsByKeyId().size(), 2);
    }

    @Test
    public void testMissingDefaultAndUnmappedKey() {
        expectThrows(CrypkiException.class, () -> new KmsCaCertificateStore(null, null).get("alias/x"));
        expectThrows(CrypkiException.class, () -> new KmsCaCertificateStore("", "").get("alias/x"));
    }

    @Test
    public void testMissingCertificateFile() throws Exception {
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore("/missing-ca.pem", null).get("alias/x"));
        java.io.File invalidPem = java.io.File.createTempFile("cacert", ".pem");
        invalidPem.deleteOnExit();
        Files.writeString(invalidPem.toPath(), "not-a-certificate\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(invalidPem.getAbsolutePath(), null).get("alias/x"));
        Files.writeString(invalidPem.toPath(),
                "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(invalidPem.getAbsolutePath(), null).get("alias/x"));
    }

    @Test
    public void testInvalidAndEmptyMap() throws Exception {
        expectThrows(CrypkiException.class, () -> new KmsCaCertificateStore(null, "/missing-map.json"));
        java.io.File invalid = java.io.File.createTempFile("camap", ".json");
        invalid.deleteOnExit();
        Files.writeString(invalid.toPath(), "{not-json");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(null, invalid.getAbsolutePath()));

        java.io.File empty = java.io.File.createTempFile("camap", ".json");
        empty.deleteOnExit();
        Files.writeString(empty.toPath(), "{}\n");
        assertTrue(new KmsCaCertificateStore(null, empty.getAbsolutePath()).getCertPathsByKeyId().isEmpty());

        java.io.File emptyMapped = java.io.File.createTempFile("camap", ".json");
        emptyMapped.deleteOnExit();
        Files.writeString(emptyMapped.toPath(), "{ \"alias/x\": \"\" }\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(null, emptyMapped.getAbsolutePath()));

        java.io.File jsonNull = java.io.File.createTempFile("camap", ".json");
        jsonNull.deleteOnExit();
        Files.writeString(jsonNull.toPath(), "null\n");
        assertTrue(new KmsCaCertificateStore(null, jsonNull.getAbsolutePath()).getCertPathsByKeyId().isEmpty());

        java.io.File nullEntry = java.io.File.createTempFile("camap", ".json");
        nullEntry.deleteOnExit();
        Files.writeString(nullEntry.toPath(), "{ \"tenant-a-ca\": null }\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(null, nullEntry.getAbsolutePath()));

        java.io.File missingPath = java.io.File.createTempFile("camap", ".json");
        missingPath.deleteOnExit();
        Files.writeString(missingPath.toPath(), "{ \"tenant-a-ca\": { \"keyId\": \"alias/x\" } }\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(null, missingPath.getAbsolutePath()));
    }

    @Test
    public void testObjectMapResolvesCloudKeyId() throws Exception {
        X509Certificate defaultCa = selfSigned("CN=default-ca");
        X509Certificate tenantA = selfSigned("CN=tenant-a-ca");
        String defaultPath = writePem(defaultCa);
        String tenantAPath = writePem(tenantA);
        String mapPath = writeMap("{\n"
                + "  \"tenant-a-ca\": {\n"
                + "    \"keyId\": \"alias/tenant-a-ca\",\n"
                + "    \"caCertPath\": \"" + jsonPath(tenantAPath) + "\"\n"
                + "  }\n"
                + "}\n");

        KmsCaCertificateStore store = new KmsCaCertificateStore(defaultPath, mapPath);
        assertEquals(store.get("tenant-a-ca").getSubjectX500Principal(),
                tenantA.getSubjectX500Principal());
        assertEquals(store.resolveCloudKeyId("tenant-a-ca"), "alias/tenant-a-ca");
        assertEquals(store.resolveCloudKeyId("alias/unknown"), "alias/unknown");
        assertEquals(store.resolveCloudKeyId(null), null);
    }

    @Test
    public void testInvalidMapValueType() throws Exception {
        java.io.File invalid = java.io.File.createTempFile("camap", ".json");
        invalid.deleteOnExit();
        Files.writeString(invalid.toPath(), "[\"not-an-object\"]\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(null, invalid.getAbsolutePath()));

        java.io.File badEntry = java.io.File.createTempFile("camap", ".json");
        badEntry.deleteOnExit();
        Files.writeString(badEntry.toPath(), "{ \"tenant-a-ca\": 12 }\n");
        expectThrows(CrypkiException.class,
                () -> new KmsCaCertificateStore(null, badEntry.getAbsolutePath()));

        ObjectMapper mapper = new ObjectMapper();
        expectThrows(CrypkiException.class, () -> KmsCaCertificateStore.mappingFromNode("x", null));
        expectThrows(CrypkiException.class,
                () -> KmsCaCertificateStore.mappingFromNode("x", mapper.readTree("null")));
        expectThrows(CrypkiException.class,
                () -> KmsCaCertificateStore.requireCertPath("x", null, null));
        expectThrows(CrypkiException.class,
                () -> KmsCaCertificateStore.requireCertPath("x", null, "   "));
        assertEquals(KmsCaCertificateStore.textOrEmpty(null), "");
        assertEquals(KmsCaCertificateStore.textOrEmpty(mapper.readTree("1")), "");
        assertEquals(KmsCaCertificateStore.textOrEmpty(mapper.readTree("\"alias/x\"")), "alias/x");
        assertEquals(KmsCaCertificateStore.requireCertPath("x", "alias/x", " /ca.pem ").caCertPath,
                "/ca.pem");
    }

    @Test
    public void testCachesCertificateForProcessLifetime() throws Exception {
        X509Certificate first = selfSigned("CN=first-ca");
        X509Certificate second = selfSigned("CN=second-ca");
        String path = writePem(first);
        KmsCaCertificateStore store = new KmsCaCertificateStore(path, null);
        assertEquals(store.get(null).getSubjectX500Principal(), first.getSubjectX500Principal());
        assertEquals(store.get("alias/other").getSubjectX500Principal(),
                first.getSubjectX500Principal());
        Files.writeString(Path.of(path), Crypto.convertToPEMFormat(second));
        assertEquals(store.get(null).getSubjectX500Principal(), first.getSubjectX500Principal());
        KmsCaCertificateStore restarted = new KmsCaCertificateStore(path, null);
        assertEquals(restarted.get(null).getSubjectX500Principal(),
                second.getSubjectX500Principal());
    }

    @Test
    public void testFromProperties() throws Exception {
        X509Certificate ca = selfSigned("CN=prop-ca");
        X509Certificate tenant = selfSigned("CN=prop-tenant");
        String path = writePem(ca);
        String tenantPath = writePem(tenant);
        String mapPath = writeMap("{ \"tenant-a-ca\": \"" + jsonPath(tenantPath) + "\" }\n");
        System.setProperty(CrypkiConsts.PROP_KMS_CA_CERT_PATH, path);
        System.setProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH, mapPath);
        try {
            KmsCaCertificateStore store = KmsCaCertificateStore.fromProperties();
            assertEquals(store.get("alias/x").getSubjectX500Principal(),
                    ca.getSubjectX500Principal());
            assertEquals(store.get("tenant-a-ca").getSubjectX500Principal(),
                    tenant.getSubjectX500Principal());
            assertEquals(store.resolveCloudKeyId("tenant-a-ca"), "tenant-a-ca");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_KMS_CA_CERT_PATH);
            System.clearProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH);
        }
    }

    @Test
    public void testFromHsmProperties() throws Exception {
        X509Certificate ca = selfSigned("CN=hsm-ca");
        X509Certificate tenant = selfSigned("CN=hsm-tenant");
        String path = writePem(ca);
        String tenantPath = writePem(tenant);
        String mapPath = writeMap("{ \"tenant-b-ca\": { \"keyId\": \"athenz-crypki-tenant-b-ca\","
                + " \"caCertPath\": \"" + jsonPath(tenantPath) + "\" } }\n");
        System.setProperty(CrypkiConsts.PROP_HSM_CA_CERT_PATH, path);
        System.setProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH, mapPath);
        try {
            KmsCaCertificateStore store = KmsCaCertificateStore.fromHsmProperties();
            assertEquals(store.get(null).getSubjectX500Principal(), ca.getSubjectX500Principal());
            assertEquals(store.get("tenant-b-ca").getSubjectX500Principal(),
                    tenant.getSubjectX500Principal());
            assertEquals(store.resolveCloudKeyId("tenant-b-ca"), "athenz-crypki-tenant-b-ca");
            CrypkiException missing = expectThrows(CrypkiException.class,
                    () -> new KmsCaCertificateStore(null, null, CrypkiConsts.PROP_HSM_CA_CERT_PATH)
                            .get("tenant-b-ca"));
            assertTrue(missing.getMessage().contains(CrypkiConsts.PROP_HSM_CA_CERT_PATH));
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_CA_CERT_PATH);
            System.clearProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH);
        }
    }

    private static X509Certificate selfSigned(String dn) throws Exception {
        var key = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(key, dn + ",O=Athenz,C=US", null);
        return Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), key,
                new org.bouncycastle.asn1.x500.X500Name(dn + ",O=Athenz,C=US"), 60, true);
    }

    private static String writePem(X509Certificate ca) throws Exception {
        java.io.File file = java.io.File.createTempFile("cacert", ".pem");
        file.deleteOnExit();
        Files.writeString(file.toPath(), Crypto.convertToPEMFormat(ca));
        return file.getAbsolutePath();
    }

    private static String writeMap(String json) throws Exception {
        java.io.File file = java.io.File.createTempFile("camap", ".json");
        file.deleteOnExit();
        Files.writeString(file.toPath(), json);
        return file.getAbsolutePath();
    }

    private static String jsonPath(String path) {
        return path.replace("\\", "\\\\");
    }
}

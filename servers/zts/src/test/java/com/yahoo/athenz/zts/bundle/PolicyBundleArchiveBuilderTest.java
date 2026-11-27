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
package com.yahoo.athenz.zts.bundle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.PolicyBundle;
import com.yahoo.athenz.zms.PolicyBundleFile;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import static org.testng.Assert.*;

public class PolicyBundleArchiveBuilderTest {

    private static final SignatureHasher HASHER = new SignatureHasher(SignatureHasher.Algorithm.SHA256);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long MODIFIED_MILLIS = 1700000000123L;

    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;

    @BeforeClass
    public void setup() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = ecGen.generateKeyPair();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair = rsaGen.generateKeyPair();
    }

    private PolicyBundleFile file(String path, String content) throws IOException {
        return new PolicyBundleFile().setPath(path).setContent(content)
                .setSha256(HexFormat.of().formatHex(Crypto.sha256(content.getBytes(StandardCharsets.UTF_8))));
    }

    private PolicyBundle regoBundle() throws IOException {
        return new PolicyBundle().setName("sports:bundle.api").setEngine("rego").setVersion("v1")
                .setModified(Timestamp.fromMillis(MODIFIED_MILLIS))
                .setFiles(new ArrayList<>(Arrays.asList(
                        file("sports/api/policy.rego", "package sports.api\n\nallow = true\n"),
                        file("sports/api/data.json", "{ \"b\": 1, \"a\": [1, 2] }"))));
    }

    private ServerPrivateKey ecKey() {
        return new ServerPrivateKey(ecKeyPair.getPrivate(), "ec-1");
    }

    private ServerPrivateKey rsaKey() {
        return new ServerPrivateKey(rsaKeyPair.getPrivate(), "rsa-1");
    }

    private Map<String, byte[]> untar(byte[] archive) throws IOException {
        return TarTestUtils.readTar(TarTestUtils.gunzip(archive));
    }

    private JsonNode json(byte[] data) throws IOException {
        return MAPPER.readTree(data);
    }

    private boolean verifyJwt(String jwt, PublicKey key, String jdkAlgorithm) throws Exception {
        String[] parts = jwt.split("\\.");
        assertEquals(parts.length, 3);
        Signature sig = Signature.getInstance(jdkAlgorithm);
        sig.initVerify(key);
        sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getUrlDecoder().decode(parts[2]));
    }

    @Test
    public void testGetRevision() {
        PolicyBundle bundle = new PolicyBundle();
        assertEquals(PolicyBundleArchiveBuilder.getRevision(bundle), "0");
        bundle.setModified(Timestamp.fromMillis(MODIFIED_MILLIS));
        assertEquals(PolicyBundleArchiveBuilder.getRevision(bundle), Timestamp.fromMillis(MODIFIED_MILLIS).toString());
    }

    @Test
    public void testGetRoots() {
        PolicyBundle bundle = new PolicyBundle();
        assertEquals(PolicyBundleArchiveBuilder.getRoots("sports.prod", "api.v1", bundle),
                Collections.singletonList("sports/prod/api/v1"));
        bundle.setRoots(new ArrayList<>());
        assertEquals(PolicyBundleArchiveBuilder.getRoots("sports", "api", bundle),
                Collections.singletonList("sports/api"));
        bundle.setRoots(Arrays.asList("r1", "r2"));
        assertEquals(PolicyBundleArchiveBuilder.getRoots("sports", "api", bundle), Arrays.asList("r1", "r2"));
    }

    @Test
    public void testBuildRegoEcSigned() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        PolicyBundle bundle = regoBundle();
        byte[] archive = builder.build("sports", "api", bundle, null, ecKey());

        Map<String, byte[]> entries = untar(archive);

        // order: signatures, manifest, bundle files, athenz files

        assertEquals(new ArrayList<>(entries.keySet()), Arrays.asList(".signatures.json", ".manifest",
                "sports/api/policy.rego", "sports/api/data.json"));

        // bundle file content is unchanged

        assertEquals(new String(entries.get("sports/api/policy.rego"), StandardCharsets.UTF_8),
                "package sports.api\n\nallow = true\n");
        assertEquals(new String(entries.get("sports/api/data.json"), StandardCharsets.UTF_8),
                "{ \"b\": 1, \"a\": [1, 2] }");

        // manifest

        JsonNode manifest = json(entries.get(".manifest"));
        assertEquals(manifest.get("revision").asText(), Timestamp.fromMillis(MODIFIED_MILLIS).toString());
        assertEquals(manifest.get("roots").size(), 1);
        assertEquals(manifest.get("roots").get(0).asText(), "sports/api");
        JsonNode metadata = manifest.get("metadata");
        assertEquals(metadata.get("engine").asText(), "rego");
        assertEquals(metadata.get("domain").asText(), "sports");
        assertEquals(metadata.get("bundle").asText(), "api");
        assertEquals(metadata.get("version").asText(), "v1");

        // jwt signatures

        JsonNode signatures = json(entries.get(".signatures.json"));
        assertEquals(signatures.get("signatures").size(), 1);
        String jwt = signatures.get("signatures").get(0).asText();
        String[] parts = jwt.split("\\.");

        JsonNode header = json(Base64.getUrlDecoder().decode(parts[0]));
        assertEquals(header.get("alg").asText(), "ES256");
        assertEquals(header.get("kid").asText(), "ec-1");
        assertEquals(header.get("typ").asText(), "JWT");

        JsonNode payload = json(Base64.getUrlDecoder().decode(parts[1]));
        assertEquals(payload.get("scope").asText(), "sports:bundle.api");

        // ES256 signatures must be in P1363 format - 64 bytes for P-256

        assertEquals(Base64.getUrlDecoder().decode(parts[2]).length, 64);
        assertTrue(verifyJwt(jwt, ecKeyPair.getPublic(), "SHA256withECDSAinP1363Format"));

        // also verify through our Crypto helper by converting to DER

        byte[] p1363 = Base64.getUrlDecoder().decode(parts[2]);
        byte[] der = Crypto.convertSignatureFromP1363ToDERFormat(p1363, Crypto.SHA256);
        assertTrue(Crypto.verify((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8),
                ecKeyPair.getPublic(), der, Crypto.SHA256));

        // file list - hashes match OPA digests of every file in the archive
        // other than the signatures file itself

        JsonNode files = json(Base64.getUrlDecoder().decode(parts[1])).get("files");
        assertEquals(files.size(), entries.size() - 1);
        Set<String> names = new HashSet<>();
        for (JsonNode fileInfo : files) {
            String name = fileInfo.get("name").asText();
            names.add(name);
            assertEquals(fileInfo.get("algorithm").asText(), "SHA-256");
            assertEquals(fileInfo.get("hash").asText(), HASHER.hashBundleFileHex(name, entries.get(name)), name);
        }
        assertEquals(names.size(), files.size());
        assertFalse(names.contains(".signatures.json"));
        assertTrue(names.contains(".manifest"));

        // data.json hash is the canonical json one and not the raw bytes hash

        String rawHash = HexFormat.of().formatHex(Crypto.sha256(entries.get("sports/api/data.json")));
        for (JsonNode fileInfo : files) {
            if (fileInfo.get("name").asText().equals("sports/api/data.json")) {
                assertNotEquals(fileInfo.get("hash").asText(), rawHash);
                assertEquals(fileInfo.get("hash").asText(),
                        HASHER.hashBundleFileHex("x/data.json", "{\"a\":[1,2],\"b\":1}".getBytes()));
            }
        }

        // tamper with the payload - signature must not verify

        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"files\":[]}".getBytes()) + "." + parts[2];
        assertFalse(verifyJwt(tampered, ecKeyPair.getPublic(), "SHA256withECDSAinP1363Format"));
    }

    @Test
    public void testBuildRsaSigned() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        byte[] archive = builder.build("sports", "api", regoBundle(), null, rsaKey());
        Map<String, byte[]> entries = untar(archive);

        String jwt = json(entries.get(".signatures.json")).get("signatures").get(0).asText();
        String[] parts = jwt.split("\\.");
        JsonNode header = json(Base64.getUrlDecoder().decode(parts[0]));
        assertEquals(header.get("alg").asText(), "RS256");
        assertEquals(header.get("kid").asText(), "rsa-1");
        assertEquals(Base64.getUrlDecoder().decode(parts[2]).length, 256);
        assertTrue(verifyJwt(jwt, rsaKeyPair.getPublic(), "SHA256withRSA"));
        assertTrue(Crypto.verify((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8),
                rsaKeyPair.getPublic(), Base64.getUrlDecoder().decode(parts[2]), Crypto.SHA256));
    }

    @Test
    public void testBuildUnsigned() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        byte[] archive = builder.build("sports", "api", regoBundle(), null, null);
        Map<String, byte[]> entries = untar(archive);
        assertFalse(entries.containsKey(".signatures.json"));
        assertEquals(new ArrayList<>(entries.keySet()).get(0), ".manifest");
    }

    @Test
    public void testBuildRegoWithJwks() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        final String jwks = "{\"keys\":[{\"kid\":\"0\"}]}";

        // default root is derived from the domain and bundle name

        Map<String, byte[]> entries = untar(builder.build("sports", "api", regoBundle(), jwks, ecKey()));
        assertEquals(new String(entries.get("sports/api/athenz/zts/keys/data.json"), StandardCharsets.UTF_8), jwks);

        // under the first explicit root when roots are specified

        PolicyBundle bundle = regoBundle().setRoots(Arrays.asList("custom/first", "custom/second"));
        entries = untar(builder.build("sports", "api", bundle, jwks, null));
        assertEquals(new String(entries.get("custom/first/athenz/zts/keys/data.json"), StandardCharsets.UTF_8), jwks);
        assertFalse(entries.containsKey("custom/second/athenz/zts/keys/data.json"));

        // a bundle file with the same path takes precedence

        bundle = regoBundle();
        bundle.getFiles().add(file("sports/api/athenz/zts/keys/data.json", "{\"mine\":true}"));
        entries = untar(builder.build("sports", "api", bundle, jwks, null));
        assertEquals(new String(entries.get("sports/api/athenz/zts/keys/data.json"), StandardCharsets.UTF_8),
                "{\"mine\":true}");

        // no jwks - no file

        entries = untar(builder.build("sports", "api", regoBundle(), null, null));
        assertFalse(entries.containsKey("sports/api/athenz/zts/keys/data.json"));
    }

    @Test
    public void testBuildWithoutModifiedTimestamp() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        PolicyBundle bundle = regoBundle().setModified(null);
        Map<String, Long> mtimes = new HashMap<>();
        byte[] tar = TarTestUtils.gunzip(builder.build("sports", "api", bundle, null, null));
        TarTestUtils.readTar(tar, mtimes);
        assertEquals(mtimes.get(".manifest").longValue(), 0L);
        assertEquals(json(TarTestUtils.readTar(tar).get(".manifest")).get("revision").asText(), "0");

        // with the timestamp - tar mtime is in seconds

        mtimes.clear();
        tar = TarTestUtils.gunzip(builder.build("sports", "api", regoBundle(), null, null));
        TarTestUtils.readTar(tar, mtimes);
        assertEquals(mtimes.get(".manifest").longValue(), MODIFIED_MILLIS / 1000);
    }

    @Test
    public void testBuildIsDeterministic() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        // unsigned archives are fully deterministic (gzip header carries no timestamp)
        byte[] a1 = builder.build("sports", "api", regoBundle(), null, null);
        byte[] a2 = builder.build("sports", "api", regoBundle(), null, null);
        assertEquals(a1, a2);
    }

    @Test
    public void testBuildLongFilePath() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        String path = "sports/api/" + "nested/".repeat(30) + "policy.rego";
        PolicyBundle bundle = regoBundle();
        bundle.getFiles().add(file(path, "package long\n"));
        Map<String, byte[]> entries = untar(builder.build("sports", "api", bundle, null, ecKey()));
        assertEquals(new String(entries.get(path), StandardCharsets.UTF_8), "package long\n");
    }

    @Test
    public void testBuildInvalidDataJson() throws Exception {
        PolicyBundleArchiveBuilder builder = new PolicyBundleArchiveBuilder();
        PolicyBundle bundle = regoBundle();
        bundle.getFiles().add(file("sports/api/sub/data.json", "{not json"));

        // the digest is only computed when signing

        try {
            builder.build("sports", "api", bundle, null, ecKey());
            fail();
        } catch (IOException ex) {
            assertNotNull(ex.getMessage());
        }
        assertNotNull(builder.build("sports", "api", bundle, null, null));
    }
}

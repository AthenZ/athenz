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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.PolicyBundle;
import com.yahoo.athenz.zms.PolicyBundleFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPOutputStream;

/**
 * Builds an OPA bundle archive (gzipped tar) for a policy bundle.
 */
public class PolicyBundleArchiveBuilder {

    public static final String ENGINE_REGO = "rego";

    static final String FILE_MANIFEST = ".manifest";
    static final String FILE_SIGNATURES = ".signatures.json";
    static final String FILE_JWKS_DATA = "athenz/zts/keys/data.json";
    static final String HASH_ALGORITHM = "SHA-256";
    private static final SignatureHasher HASHER = new SignatureHasher(SignatureHasher.Algorithm.SHA256);

    private final ObjectMapper jsonMapper;

    public PolicyBundleArchiveBuilder() {
        jsonMapper = new ObjectMapper();
        jsonMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Return the bundle revision - the bundle modification timestamp which
     * changes when the bundle content or its active version is updated
     * @param bundle policy bundle
     * @return revision string
     */
    public static String getRevision(PolicyBundle bundle) {
        return bundle.getModified() == null ? "0" : bundle.getModified().toString();
    }

    /**
     * Return the manifest roots for the bundle. If the bundle does not specify
     * any roots then a single root is derived from the domain and bundle name
     * (e.g. sports.prod + api.v1 = sports/prod/api/v1) so multiple bundles can
     * be loaded into the same OPA instance without overlapping.
     * @param domainName name of the domain
     * @param bundleName name of the bundle
     * @param bundle policy bundle
     * @return list of roots
     */
    public static List<String> getRoots(final String domainName, final String bundleName, PolicyBundle bundle) {
        List<String> roots = bundle.getRoots();
        if (roots != null && !roots.isEmpty()) {
            return roots;
        }
        return Collections.singletonList(domainName.replace('.', '/') + "/" + bundleName.replace('.', '/'));
    }

    /**
     * Build the gzipped tar archive for the bundle
     * @param domainName name of the domain
     * @param bundleName name of the bundle
     * @param bundle policy bundle (active version)
     * @param jwksData optional json document with the ZTS public keys to be
     *                 included in the bundle as data (null to skip)
     * @param signingKey optional key used to generate .signatures.json (null to skip)
     * @return archive bytes
     * @throws IOException in case of any failures
     */
    public byte[] build(final String domainName, final String bundleName, PolicyBundle bundle,
            final String jwksData, ServerPrivateKey signingKey) throws IOException {

        final List<String> roots = getRoots(domainName, bundleName, bundle);

        // collect our files in order: bundle files followed by athenz
        // generated files

        Map<String, byte[]> files = new LinkedHashMap<>();
        for (PolicyBundleFile file : bundle.getFiles()) {
            files.put(file.getPath(), file.getContent().getBytes(StandardCharsets.UTF_8));
        }

        if (jwksData != null) {
            // data files must be under one of the bundle roots so we
            // place the keys under the first root. a bundle file with
            // the same path takes precedence
            final String jwksPath = roots.get(0) + "/" + FILE_JWKS_DATA;
            files.putIfAbsent(jwksPath, jwksData.getBytes(StandardCharsets.UTF_8));
        }

        final byte[] manifest = generateManifest(domainName, bundleName, bundle, roots);

        TarArchiveWriter tarWriter = new TarArchiveWriter(bundle.getModified() == null ? 0
                : bundle.getModified().millis() / 1000);
        if (signingKey != null) {
            tarWriter.addFile(FILE_SIGNATURES, generateSignatures(manifest, files, signingKey));
        }
        tarWriter.addFile(FILE_MANIFEST, manifest);
        for (Map.Entry<String, byte[]> entry : files.entrySet()) {
            tarWriter.addFile(entry.getKey(), entry.getValue());
        }

        ByteArrayOutputStream gzipBytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(gzipBytes)) {
            gzip.write(tarWriter.finish());
        }
        return gzipBytes.toByteArray();
    }

    byte[] generateManifest(final String domainName, final String bundleName, PolicyBundle bundle,
            List<String> roots) throws IOException {

        Map<String, Object> metadata = new TreeMap<>();
        metadata.put("engine", bundle.getEngine());
        metadata.put("domain", domainName);
        metadata.put("bundle", bundleName);
        metadata.put("version", bundle.getVersion());

        Map<String, Object> manifest = new TreeMap<>();
        manifest.put("revision", getRevision(bundle));
        manifest.put("roots", roots);
        manifest.put("metadata", metadata);
        return jsonMapper.writeValueAsBytes(manifest);
    }

    byte[] generateSignatures(final byte[] manifest, Map<String, byte[]> files, ServerPrivateKey signingKey)
            throws IOException {

        List<Map<String, String>> fileInfoList = new ArrayList<>();
        fileInfoList.add(fileInfo(FILE_MANIFEST, manifest));
        for (Map.Entry<String, byte[]> entry : files.entrySet()) {
            fileInfoList.add(fileInfo(entry.getKey(), entry.getValue()));
        }

        Map<String, Object> payload = new TreeMap<>();
        payload.put("files", fileInfoList);

        Map<String, String> header = new TreeMap<>();
        header.put("alg", signingKey.getAlgorithm());
        header.put("kid", signingKey.getId());
        header.put("typ", "JWT");

        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final String signingInput = encoder.encodeToString(jsonMapper.writeValueAsBytes(header)) + "."
                + encoder.encodeToString(jsonMapper.writeValueAsBytes(payload));

        byte[] signature = Crypto.sign(signingInput.getBytes(StandardCharsets.UTF_8),
                signingKey.getKey(), Crypto.SHA256);

        // JWS signatures for EC keys must be in P1363 (R || S) format

        if (Crypto.ES256.equals(signingKey.getAlgorithm())) {
            signature = Crypto.convertSignatureFromDERToP1363Format(signature, Crypto.SHA256);
        }
        final String jwt = signingInput + "." + encoder.encodeToString(signature);

        Map<String, Object> signatures = new TreeMap<>();
        signatures.put("signatures", Collections.singletonList(jwt));
        return jsonMapper.writeValueAsBytes(signatures);
    }

    Map<String, String> fileInfo(final String path, final byte[] content) throws IOException {
        Map<String, String> fileInfo = new TreeMap<>();
        fileInfo.put("name", path);
        fileInfo.put("hash", HASHER.hashBundleFileHex(path, content));
        fileInfo.put("algorithm", HASH_ALGORITHM);
        return fileInfo;
    }
}

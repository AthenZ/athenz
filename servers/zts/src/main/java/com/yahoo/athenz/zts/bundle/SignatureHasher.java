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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.CharacterEscapes;
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class SignatureHasher {

    // 1. Supported hashing algorithms matching OPA constants
    public enum Algorithm {
        SHA256("SHA-256", "SHA-256"),
        SHA384("SHA-384", "SHA-384"),
        SHA512("SHA-512", "SHA-512");

        private final String value;
        private final String jceAlgorithm;

        Algorithm(String value, String jceAlgorithm) {
            this.value = value;
            this.jceAlgorithm = jceAlgorithm;
        }

        public String getValue() {
            return value;
        }

        public MessageDigest createDigest() throws NoSuchAlgorithmException {
            return MessageDigest.getInstance(this.jceAlgorithm);
        }

        public static Algorithm fromString(String name) {
            for (Algorithm alg : values()) {
                if (alg.value.equalsIgnoreCase(name)) {
                    return alg;
                }
            }
            throw new IllegalArgumentException("Unsupported hashing algorithm: " + name);
        }
    }

    // 2. Metadata representation matching FileInfo in hash.go
    public record FileInfo(String name, String hash, Algorithm algorithm) { }

    /**
     * Go encoding/json (with html escaping disabled) additionally escapes the
     * line and paragraph separators. Jackson already matches Go for the
     * quote, backslash and control characters and does not escape html.
     */
    private static final class GoCharacterEscapes extends CharacterEscapes {

        private static final SerializableString LINE_SEPARATOR = new SerializedString("\\u2028");
        private static final SerializableString PARAGRAPH_SEPARATOR = new SerializedString("\\u2029");

        private final int[] asciiEscapes = CharacterEscapes.standardAsciiEscapesForJSON();

        @Override
        public int[] getEscapeCodesForAscii() {
            return asciiEscapes;
        }

        @Override
        public SerializableString getEscapeSequence(int ch) {
            return switch (ch) {
                case 0x2028 -> LINE_SEPARATOR;
                case 0x2029 -> PARAGRAPH_SEPARATOR;
                default -> null;
            };
        }
    }

    // Jackson mapper configured to match Go's deterministic json.Marshal encoding:
    // sorted keys, no whitespace, numbers without exponent and Go string escaping

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder(
                    new JsonFactory().setCharacterEscapes(new GoCharacterEscapes()))
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN)
            .build();

    // bundle files whose content OPA hashes as canonical json instead of raw bytes

    private static final String FILE_DATA_JSON = "data.json";
    private static final String FILE_MANIFEST = ".manifest";

    private final Algorithm algorithm;

    public SignatureHasher(Algorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        // Fail-fast if the algorithm is unavailable in the JVM security provider
        try {
            algorithm.createDigest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm not supported by runtime: " + algorithm, e);
        }
        this.algorithm = algorithm;
    }

    /**
     * Hashes file content. Supports byte[], String, InputStream, or arbitrary objects
     * (serialized into canonical sorted JSON, matching Go's json.Marshal).
     */
    public byte[] hashFile(Object value) throws Exception {
        if (value == null) {
            return new byte[0];
        }

        MessageDigest digest = algorithm.createDigest();

        if (value instanceof byte[] bytes) {
            digest.update(bytes);
        } else if (value instanceof String str) {
            digest.update(str.getBytes(StandardCharsets.UTF_8));
        } else if (value instanceof InputStream in) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        } else {
            byte[] jsonBytes = OBJECT_MAPPER.writeValueAsBytes(value);
            digest.update(jsonBytes);
        }

        return digest.digest();
    }

    /**
     * Computes the hash and returns it as a lowercase hex string.
     */
    public String hashFileHex(Object value) throws Exception {
        return HexFormat.of().formatHex(hashFile(value));
    }

    /**
     * Helper to compute hash and wrap it into a FileInfo record.
     */
    public FileInfo createFileInfo(String filename, Object value) throws Exception {
        return new FileInfo(filename, hashFileHex(value), this.algorithm);
    }

    public static boolean isStructuredFile(final String path) {
        final String fileName = path.substring(path.lastIndexOf('/') + 1);
        return FILE_DATA_JSON.equals(fileName) || FILE_MANIFEST.equals(fileName);
    }

    /**
     * Hashes a bundle file the way OPA does: structured files (data.json,
     * .manifest) are parsed and hashed in their canonical json form,
     * all other files are hashed as raw bytes.
     * @param path path of the file in the bundle
     * @param content file content
     * @return lowercase hex encoded hash
     * @throws IOException if a structured file is not valid json
     */
    public String hashBundleFileHex(final String path, final byte[] content) throws IOException {
        try {
            if (isStructuredFile(path)) {
                // serialize first since hashFile treats a String as raw text
                // and a top level json string must keep its quotes
                final Object value = OBJECT_MAPPER.readValue(content, Object.class);
                return hashFileHex(OBJECT_MAPPER.writeValueAsBytes(value));
            }
            return hashFileHex(content);
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }
}

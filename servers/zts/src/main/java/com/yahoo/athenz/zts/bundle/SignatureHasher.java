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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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

    // Jackson mapper configured to match Go's deterministic json.Marshal encoding:
    // keys sorted by utf-8 bytes, no whitespace, numbers without exponent and Go string escaping

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN)
            .addModule(new SimpleModule().addSerializer(RawNumber.class, new RawNumberSerializer()))
            .build();

    // bundle files whose content OPA hashes as canonical json instead of raw bytes

    private static final String FILE_DATA_JSON = "data.json";
    private static final String FILE_MANIFEST = ".manifest";

    // Go sorts map keys by their utf-8 bytes, which differs from String's
    // utf-16 code unit order for supplementary characters vs. U+E000-U+FFFF

    private static final Comparator<String> UTF8_KEY_ORDER = (a, b) -> Arrays.compareUnsigned(
            a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));

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

    /**
     * OPA decodes json with UseNumber so numbers keep their original token
     * spelling (1e3, -0, 1.0) when it re-encodes the document for hashing.
     * We parse the document ourselves and keep the number tokens as is,
     * sort the object keys and drop all whitespace.
     * @param content json document
     * @return canonical json bytes
     * @throws IOException if the content is not exactly one valid json document
     */
    static byte[] canonicalJson(final byte[] content) throws IOException {
        try (JsonParser parser = OBJECT_MAPPER.getFactory().createParser(content)) {
            if (parser.nextToken() == null) {
                throw new IOException("empty json document");
            }
            final Object value = readValue(parser);
            if (parser.nextToken() != null) {
                throw new IOException("unexpected trailing content after json document");
            }
            return toGoJson(value);
        }
    }

    // Go encoding/json (with html escaping disabled) escapes the line and paragraph
    // separators and writes every other non-ascii character, including supplementary
    // ones, as raw utf-8. Jackson's utf-8 byte generator escapes supplementary
    // characters as surrogate pairs, so serialize to a string and encode it here.

    private static byte[] toGoJson(final Object value) throws IOException {
        return OBJECT_MAPPER.writeValueAsString(value)
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static Object readValue(JsonParser parser) throws IOException {
        switch (parser.currentToken()) {
            case START_OBJECT:
                Map<String, Object> map = new TreeMap<>(UTF8_KEY_ORDER);
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    final String name = parser.currentName();
                    parser.nextToken();
                    map.put(name, readValue(parser));
                }
                return map;
            case START_ARRAY:
                List<Object> list = new ArrayList<>();
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    list.add(readValue(parser));
                }
                return list;
            case VALUE_NUMBER_INT:
            case VALUE_NUMBER_FLOAT:
                return new RawNumber(parser.getText());
            case VALUE_STRING:
                return parser.getText();
            case VALUE_TRUE:
                return Boolean.TRUE;
            case VALUE_FALSE:
                return Boolean.FALSE;
            case VALUE_NULL:
                return null;
            default:
                throw new IOException("unexpected json token: " + parser.currentToken());
        }
    }

    /** json number kept as its original text token */
    private record RawNumber(String text) { }

    private static final class RawNumberSerializer extends JsonSerializer<RawNumber> {
        @Override
        public void serialize(RawNumber value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeRawValue(value.text());
        }
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
                return hashFileHex(canonicalJson(content));
            }
            return hashFileHex(content);
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }
}

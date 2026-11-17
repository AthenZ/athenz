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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.testng.Assert.*;

public class SignatureHasherTest {

    private static final SignatureHasher HASHER = new SignatureHasher(SignatureHasher.Algorithm.SHA256);

    @DataProvider(name = "jsonDocs")
    public Object[][] jsonDocs() {
        return new Object[][] {
            // vectors verified against the OPA go hasher
            { "{\"b\":1,\"a\":\"x\"}",
                "cdab067e9f3beb32d1252cfd63e492592fecbf591b0d08cadb24bb17f3864246" },
            { "[1, {\"k\": []}, {}]",
                "1222ad4f6680f4f9fabea00858e4851c532d09e345dd7ebecdc40e28192e6a9d" },
            { "\"plain\"",
                "945603a8f587786b463c3f94fce115c0fae88fac2728cc96ddf5981cf7f61741" },
        };
    }

    @Test(dataProvider = "jsonDocs")
    public void testStructuredJson(String json, String expected) throws IOException {
        assertEquals(hash(json), expected);
    }

    @Test
    public void testNumberTokensPreserved() throws Exception {
        // OPA keeps the original number spelling (json.Number) so the
        // canonical form must not normalize exponents, -0 or trailing zeros
        String[][] docs = {
            { "{ \"n\" : 1e3 }", "{\"n\":1e3}" },
            { "[-0, 1.0, 1E+2, 0.10, 12345678901234567890123]", "[-0,1.0,1E+2,0.10,12345678901234567890123]" },
            { "{\"b\":{\"z\":-0.0,\"a\":[1e-7]},\"a\":true}", "{\"a\":true,\"b\":{\"a\":[1e-7],\"z\":-0.0}}" },
            { "-0", "-0" },
        };
        for (String[] doc : docs) {
            assertEquals(hash(doc[0]), HASHER.hashFileHex(doc[1].getBytes(StandardCharsets.UTF_8)), doc[0]);
        }
    }

    @Test
    public void testKeysSortedByUtf8Bytes() throws IOException {
        // Go sorts keys by utf-8 bytes: U+E000 (EF 80 80) sorts before U+1F600 (F0 9F 98 80),
        // while utf-16 code unit order (D83D < E000) would put the emoji first
        byte[] canonical = SignatureHasher.canonicalJson(
                "{\"\ud83d\ude00\":1,\"\ue000\":2}".getBytes(StandardCharsets.UTF_8));
        assertEquals(new String(canonical, StandardCharsets.UTF_8), "{\"\ue000\":2,\"\ud83d\ude00\":1}");
    }

    @Test
    public void testInvalidStructuredJson() {
        for (String doc : new String[] { "", "  ", "{} {}", "{\"a\":1} 2", "{bad", "[1,", "{\"a\":}" }) {
            try {
                hash(doc);
                fail(doc);
            } catch (IOException ignored) {
            }
        }
    }

    @Test
    public void testRawFile() throws IOException {
        assertEquals(HASHER.hashBundleFileHex("x.rego", "package x\n".getBytes(StandardCharsets.UTF_8)),
                "3ea66a23367f14bd3e79ebd5c296779a4c3c40ef3a2035e23863b56ab5894bc5");
        // raw files are not parsed so invalid json is fine
        assertNotNull(HASHER.hashBundleFileHex("x/data.json.txt", "{not json".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testStructuredFileNames() throws IOException {
        assertTrue(SignatureHasher.isStructuredFile(".manifest"));
        assertTrue(SignatureHasher.isStructuredFile("a/b/.manifest"));
        assertTrue(SignatureHasher.isStructuredFile("data.json"));
        assertFalse(SignatureHasher.isStructuredFile("a/mydata.json"));
        assertFalse(SignatureHasher.isStructuredFile("a/x.rego"));

        // whitespace and key order do not matter for structured files
        assertEquals(HASHER.hashBundleFileHex(".manifest", "{ \"roots\": [\"a\"], \"revision\": \"1\" }".getBytes()),
                HASHER.hashBundleFileHex("sub/.manifest", "{\"revision\":\"1\",\"roots\":[\"a\"]}".getBytes()));
    }

    @Test
    public void testCanonicalEncoding() throws Exception {
        // duplicate keys keep the last value, html is not escaped, line and
        // paragraph separators are, which matches the go encoder
        assertEquals(hash("{\"k\":1,\"k\":2}"), hash("{\"k\":2}"));
        assertEquals(hash("{ \"s\" : \"<>&\" }"), HASHER.hashFileHex("{\"s\":\"<>&\"}"));
        assertEquals(hash("{\"s\":\"a b \"}"), HASHER.hashFileHex("{\"s\":\"a\\u2028b\\u2029\"}"));
    }

    @Test
    public void testCanonicalControlCharacterEscapes() throws Exception {
        // go encodes control characters with lowercase hex digits and writes
        // the delete character raw. expected value generated with go's
        // encoding/json (html escaping disabled)
        final byte[] input = "{\"s\":\"\\u001b\\u001f\\u000b\\u007f\\b\\f\"}".getBytes(StandardCharsets.UTF_8);
        final byte[] expected = "{\"s\":\"\\u001b\\u001f\\u000b\u007f\\b\\f\"}".getBytes(StandardCharsets.UTF_8);
        assertEquals(SignatureHasher.canonicalJson(input), expected);
    }

    @Test
    public void testInvalidJson() {
        for (String doc : new String[] { "{\"a\":", "{not json}", "", "   ", "{} {}", "{}x", "[1,2" }) {
            try {
                hash(doc);
                fail("expected failure for: " + doc);
            } catch (IOException ex) {
                // expected
            }
        }
    }

    @Test
    public void testHashInputTypes() throws Exception {
        final String expected = HASHER.hashFileHex("abc".getBytes(StandardCharsets.UTF_8));
        assertEquals(HASHER.hashFileHex("abc"), expected);
        assertEquals(HASHER.hashFileHex(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8))), expected);
        assertEquals(HASHER.hashFile(null).length, 0);
        assertEquals(HASHER.createFileInfo("f", "abc").hash(), expected);
        assertEquals(SignatureHasher.Algorithm.fromString("sha-384"), SignatureHasher.Algorithm.SHA384);
        assertThrows(IllegalArgumentException.class, () -> SignatureHasher.Algorithm.fromString("md5"));
        assertThrows(IllegalArgumentException.class, () -> new SignatureHasher(null));
        assertEquals(new SignatureHasher(SignatureHasher.Algorithm.SHA512).hashFile("a").length, 64);
    }

    private String hash(String json) throws IOException {
        return HASHER.hashBundleFileHex("data.json", json.getBytes(StandardCharsets.UTF_8));
    }
}

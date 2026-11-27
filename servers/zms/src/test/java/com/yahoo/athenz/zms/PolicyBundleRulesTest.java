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
package com.yahoo.athenz.zms;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class PolicyBundleRulesTest {

    private static final String DOMAIN = "bundledom";
    private static final String BUNDLE = "b1";
    private static final String CALLER = "putPolicyBundle";

    private static final String[] PROPS = {
            ZMSConsts.ZMS_PROP_BUNDLE_ENGINES, ZMSConsts.ZMS_PROP_MAX_BUNDLE_VERSIONS,
            ZMSConsts.ZMS_PROP_MAX_BUNDLE_FILES, ZMSConsts.ZMS_PROP_MAX_BUNDLE_FILE_SIZE,
            ZMSConsts.ZMS_PROP_MAX_BUNDLE_SIZE, ZMSConsts.ZMS_PROP_MAX_BUNDLE_ROOTS,
            ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE
    };

    @BeforeMethod
    @AfterMethod
    public void clearProps() {
        for (String prop : PROPS) {
            System.clearProperty(prop);
        }
    }

    private PolicyBundleFile file(String path, String content) {
        return new PolicyBundleFile().setPath(path).setContent(content);
    }

    private PolicyBundle regoBundle(PolicyBundleFile... files) {
        return new PolicyBundle().setName(DOMAIN + ":bundle." + BUNDLE).setEngine("rego")
                .setFiles(new ArrayList<>(Arrays.asList(files)));
    }

    private void assertInvalid(PolicyBundleRules rules, PolicyBundle bundle, String msg) {
        try {
            rules.validate(DOMAIN, BUNDLE, bundle, CALLER);
            fail("expected failure: " + msg);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains(msg), ex.getMessage());
        }
    }

    @Test
    public void testDefaults() {
        PolicyBundleRules rules = new PolicyBundleRules(null);
        assertEquals(rules.getMaxVersions(), 5);
        assertEquals(rules.maxFiles, 100);
        assertEquals(rules.maxFileSize, 1048576);
        assertEquals(rules.maxBundleSize, 4194304);
        assertEquals(rules.maxRoots, 16);
        assertEquals(rules.validationMode, "enforce");
        assertTrue(rules.engines.contains("rego"));
    }

    @Test
    public void testConstructorProperties() {
        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_ENGINES, " REGO, unknown, ,");
        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE, "bogus");
        PolicyBundleRules rules = new PolicyBundleRules(null);
        assertEquals(rules.engines, Collections.singleton("rego"));
        assertEquals(rules.validationMode, "enforce");

        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE, "OFF");
        assertEquals(new PolicyBundleRules(null).validationMode, "off");
        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE, "warn");
        assertEquals(new PolicyBundleRules(null).validationMode, "warn");
    }

    @Test
    public void testValidRegoBundle() {
        PolicyBundleRules rules = new PolicyBundleRules(null);
        PolicyBundle bundle = regoBundle(file("policy.rego", "package a"), file("sub/dir/data.json", "{\"a\": 1}"),
                file("my-mod_1.v2/x.rego", "package b"))
                .setRoots(Arrays.asList("bundledom/a", "bundledom/b-c"))
                .setDescription("desc");
        rules.validate(DOMAIN, BUNDLE, bundle, CALLER);
        assertEquals(bundle.getFiles().get(0).getSha256(), PolicyBundleRules.sha256Hex("package a".getBytes()));
    }

    @Test
    public void testNameMismatchEngineDescription() {
        PolicyBundleRules rules = new PolicyBundleRules(null);
        PolicyBundle bundle = regoBundle(file("a.rego", "x")).setName("other:bundle.b1");
        assertInvalid(rules, bundle, "bundle name mismatch");

        bundle = regoBundle(file("a.rego", "x")).setEngine("wasm");
        assertInvalid(rules, bundle, "unsupported bundle engine");

        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_ENGINES, "opa");
        assertInvalid(new PolicyBundleRules(null), regoBundle(file("a.rego", "x")), "unsupported bundle engine");
        clearProps();

        bundle = regoBundle(file("a.rego", "x")).setDescription("x".repeat(4097));
        assertInvalid(rules, bundle, "description exceeds");
        bundle = regoBundle(file("a.rego", "x")).setDescription("x".repeat(4096));
        rules.validate(DOMAIN, BUNDLE, bundle, CALLER);
    }

    @Test
    public void testRootsTotalLength() {
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_ROOTS, "16");
        PolicyBundleRules rules = new PolicyBundleRules(null);

        // each root is 256 chars: 9 roots + separators exceed the 2048 column

        List<String> roots = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            roots.add(("bundledom/" + i + "a".repeat(255)).substring(0, 256));
        }
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(roots), "roots exceed maximum total length");

        // 8 roots = 8 * 256 + 7 separators = 2055 > 2048, 7 roots fit

        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(roots.subList(0, 8)),
                "roots exceed maximum total length");
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "x")).setRoots(roots.subList(0, 7)), CALLER);
    }

    @Test
    public void testRoots() {
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_ROOTS, "2");
        PolicyBundleRules rules = new PolicyBundleRules(null);

        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Arrays.asList("a", "b", "c")),
                "roots exceed maximum count");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList("a//b")),
                "invalid bundle root");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList("/a")),
                "invalid bundle root");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList("a.b")),
                "invalid bundle root");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList("a".repeat(257))),
                "invalid bundle root");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList(null)),
                "invalid bundle root");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList("otherdom")),
                "within the domain namespace");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Collections.singletonList("bundledomx")),
                "within the domain namespace");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Arrays.asList("bundledom", "otherdom/x")),
                "within the domain namespace");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Arrays.asList("bundledom", "bundledom")),
                "overlapping bundle roots");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Arrays.asList("bundledom", "bundledom/b")),
                "overlapping bundle roots");
        assertInvalid(rules, regoBundle(file("a.rego", "x")).setRoots(Arrays.asList("bundledom/b", "bundledom")),
                "overlapping bundle roots");
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "x")).setRoots(Arrays.asList("bundledom/a", "bundledom/ab")),
                CALLER);
    }

    @Test
    public void testFileCountAndSizes() {
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_FILES, "2");
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_FILE_SIZE, "10");
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_BUNDLE_SIZE, "15");
        PolicyBundleRules rules = new PolicyBundleRules(null);

        assertInvalid(rules, regoBundle(), "at least one file");
        assertInvalid(rules, new PolicyBundle().setName(DOMAIN + ":bundle." + BUNDLE).setEngine("rego"),
                "at least one file");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("b.rego", "x"), file("c.rego", "x")),
                "files exceed maximum count");
        assertInvalid(rules, regoBundle(file("a.rego", "12345678901")), "exceeds maximum size of 10");
        assertInvalid(rules, regoBundle(file("a.rego", "12345678"), file("b.rego", "12345678")),
                "bundle exceeds maximum size of 15");
        // multi-byte characters count as bytes
        assertInvalid(rules, regoBundle(file("a.rego", "éééééé")),
                "exceeds maximum size of 10");
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "1234567890")), CALLER);
    }

    @Test
    public void testFileEntries() {
        PolicyBundleRules rules = new PolicyBundleRules(null);

        List<PolicyBundleFile> files = new ArrayList<>();
        files.add(null);
        assertInvalid(rules, new PolicyBundle().setName(DOMAIN + ":bundle." + BUNDLE).setEngine("rego")
                .setFiles(files), "empty file object");

        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("a.rego", "y")), "duplicate bundle file path");
        assertInvalid(rules, regoBundle(file("a.rego", null)), "has no content");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("data.json", "{bad")), "is not valid json");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("data.json", "")), "is not valid json");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("data.json", "  \n")), "is not valid json");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("data.json", "{} {}")), "is not valid json");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("data.json", "{\"a\":1} x")), "is not valid json");
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "x"), file("data.json", " {\"a\":1}\n")), CALLER);
    }

    @Test
    public void testPaths() {
        PolicyBundleRules rules = new PolicyBundleRules(null);
        final String[] invalid = {
                null, "", "/abs.rego", "a//b.rego", "../a.rego", "a/../b.rego", "./a.rego", ".hidden.rego",
                ".manifest", "a\\b.rego", "a b.rego", "a/", "a".repeat(513) + ".rego", "-a.rego"
        };
        for (String path : invalid) {
            assertInvalid(rules, regoBundle(file(path, "x")), "invalid bundle file path");
        }
        // only the generated keys file under the first root is reserved: with the
        // default root that is <domain>/<bundle>, otherwise the first configured root
        final String defaultKeys = "bundledom/b1/athenz/zts/keys/data.json";
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file(defaultKeys, "{}")), "reserved for generated files");
        assertInvalid(rules, regoBundle(file("a.rego", "x"), file("bundledom/athenz/zts/keys/data.json", "{}"))
                .setRoots(Collections.singletonList("bundledom")), "reserved for generated files");
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("athenz.rego", "x")), CALLER);
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("athenz/a.rego", "x"), file("athenz/zts/keys/data.json", "{}")), CALLER);
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "x"), file("bundledom/athenz/zts/keys/data.json", "{}")), CALLER);
    }

    @Test
    public void testRegoFiles() {
        PolicyBundleRules rules = new PolicyBundleRules(null);
        assertInvalid(rules, regoBundle(file("a.txt", "x"), file("a.rego", "x")), "not supported for rego bundles");
        assertInvalid(rules, regoBundle(file("data.json", "{}")), "at least one policy file");
        assertInvalid(rules, regoBundle(file("data.yaml", "a: 1"), file("a.rego", "x")),
                "not supported for rego bundles");
    }

    @Test
    public void testContentValidator() {
        PolicyBundle valid = regoBundle(file("a.rego", "x"));

        // no validator - nothing to do
        new PolicyBundleRules(null).validate(DOMAIN, BUNDLE, valid, CALLER);

        // validator returning no error
        PolicyBundleRules rules = new PolicyBundleRules((d, b, bundle) -> null);
        rules.validate(DOMAIN, BUNDLE, valid, CALLER);

        // enforce mode
        rules = new PolicyBundleRules((d, b, bundle) -> "bad content");
        assertInvalid(rules, regoBundle(file("a.rego", "x")), "bundle validation failed: bad content");

        // warn mode
        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE, "warn");
        rules = new PolicyBundleRules((d, b, bundle) -> "bad content");
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "x")), CALLER);

        // off mode - validator is not even invoked
        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE, "off");
        rules = new PolicyBundleRules((d, b, bundle) -> {
            throw new IllegalStateException("must not be called");
        });
        rules.validate(DOMAIN, BUNDLE, regoBundle(file("a.rego", "x")), CALLER);
    }

    @Test
    public void testSha256Hex() {
        assertEquals(PolicyBundleRules.sha256Hex(new byte[0]),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        PolicyBundle bundle = regoBundle(file("a.rego", "abc")).setFiles(
                new ArrayList<>(Collections.singletonList(file("a.rego", "abc").setSha256("client"))));
        new PolicyBundleRules(null).validate(DOMAIN, BUNDLE, bundle, CALLER);
        assertEquals(bundle.getFiles().get(0).getSha256(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}

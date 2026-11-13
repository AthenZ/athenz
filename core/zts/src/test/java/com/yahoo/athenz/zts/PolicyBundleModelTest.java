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

import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class PolicyBundleModelTest {

    private PolicyBundleFileData fileData(String path) {
        return new PolicyBundleFileData().setPath(path).setContent("package x").setSha256("abc");
    }

    @Test
    public void testPolicyBundleFileData() {

        PolicyBundleFileData f1 = fileData("x.rego");
        PolicyBundleFileData f2 = fileData("x.rego");

        assertEquals(f1.getPath(), "x.rego");
        assertEquals(f1.getContent(), "package x");
        assertEquals(f1.getSha256(), "abc");

        assertEquals(f1, f1);
        assertEquals(f1, f2);
        assertFalse(f1.equals(null));
        assertFalse(f1.equals("string"));

        f2.setPath("y.rego");
        assertNotEquals(f1, f2);
        f2.setPath(null);
        assertNotEquals(f1, f2);
        f2.setPath("x.rego");
        assertEquals(f1, f2);

        f2.setContent("other");
        assertNotEquals(f1, f2);
        f2.setContent(null);
        assertNotEquals(f1, f2);
        f2.setContent("package x");
        assertEquals(f1, f2);

        f2.setSha256("def");
        assertNotEquals(f1, f2);
        f2.setSha256(null);
        assertNotEquals(f1, f2);
        f2.setSha256("abc");
        assertEquals(f1, f2);

        Validator.Result result = new Validator(ZTSSchema.instance()).validate(f1, "PolicyBundleFileData");
        assertTrue(result.valid);
        result = new Validator(ZTSSchema.instance()).validate(new PolicyBundleFileData().setPath("x"),
                "PolicyBundleFileData");
        assertFalse(result.valid);
    }

    private PolicyBundleData bundleData(List<String> roots, List<PolicyBundleFileData> files) {
        return new PolicyBundleData().setDomain("sports").setName("api").setEngine("rego")
                .setVersion("v1").setRevision("100").setRoots(roots).setFiles(files);
    }

    @Test
    public void testPolicyBundleData() {

        List<String> roots = new ArrayList<>(Arrays.asList("sports/api"));
        List<PolicyBundleFileData> files = new ArrayList<>(Arrays.asList(fileData("x.rego")));
        PolicyBundleData b1 = bundleData(roots, files);
        PolicyBundleData b2 = bundleData(new ArrayList<>(roots), new ArrayList<>(files));

        assertEquals(b1.getDomain(), "sports");
        assertEquals(b1.getName(), "api");
        assertEquals(b1.getEngine(), "rego");
        assertEquals(b1.getVersion(), "v1");
        assertEquals(b1.getRevision(), "100");
        assertEquals(b1.getRoots(), roots);
        assertEquals(b1.getFiles(), files);

        assertEquals(b1, b1);
        assertEquals(b1, b2);
        assertFalse(b1.equals(null));
        assertFalse(b1.equals("string"));

        b2.setDomain("other");
        assertNotEquals(b1, b2);
        b2.setDomain(null);
        assertNotEquals(b1, b2);
        b2.setDomain("sports");
        assertEquals(b1, b2);

        b2.setName("other");
        assertNotEquals(b1, b2);
        b2.setName(null);
        assertNotEquals(b1, b2);
        b2.setName("api");
        assertEquals(b1, b2);

        b2.setEngine("other");
        assertNotEquals(b1, b2);
        b2.setEngine(null);
        assertNotEquals(b1, b2);
        b2.setEngine("rego");
        assertEquals(b1, b2);

        b2.setVersion("v2");
        assertNotEquals(b1, b2);
        b2.setVersion(null);
        assertNotEquals(b1, b2);
        b2.setVersion("v1");
        assertEquals(b1, b2);

        b2.setRevision("200");
        assertNotEquals(b1, b2);
        b2.setRevision(null);
        assertNotEquals(b1, b2);
        b2.setRevision("100");
        assertEquals(b1, b2);

        b2.setRoots(Arrays.asList("other"));
        assertNotEquals(b1, b2);
        b2.setRoots(null);
        assertNotEquals(b1, b2);
        b2.setRoots(new ArrayList<>(roots));
        assertEquals(b1, b2);

        b2.setFiles(Arrays.asList(fileData("y.rego")));
        assertNotEquals(b1, b2);
        b2.setFiles(null);
        assertNotEquals(b1, b2);
        b2.setFiles(new ArrayList<>(files));
        assertEquals(b1, b2);

        Validator validator = new Validator(ZTSSchema.instance());
        assertTrue(validator.validate(b1, "PolicyBundleData").valid);

        // optional fields can be omitted but required ones cannot

        PolicyBundleData minimal = bundleData(null, files);
        assertTrue(validator.validate(minimal, "PolicyBundleData").valid);
        assertFalse(validator.validate(minimal.setFiles(null), "PolicyBundleData").valid);
        assertFalse(validator.validate(bundleData(null, files).setDomain(null), "PolicyBundleData").valid);
        assertFalse(validator.validate(bundleData(null, files).setName("bad name!"), "PolicyBundleData").valid);
    }

    private PolicyBundleEntry entry() {
        return new PolicyBundleEntry().setDomain("sports").setName("api").setEngine("rego")
                .setVersion("v1").setRevision("100");
    }

    @Test
    public void testPolicyBundleEntry() {

        PolicyBundleEntry e1 = entry();
        PolicyBundleEntry e2 = entry();

        assertEquals(e1.getDomain(), "sports");
        assertEquals(e1.getName(), "api");
        assertEquals(e1.getEngine(), "rego");
        assertEquals(e1.getVersion(), "v1");
        assertEquals(e1.getRevision(), "100");

        assertEquals(e1, e1);
        assertEquals(e1, e2);
        assertFalse(e1.equals(null));
        assertFalse(e1.equals("string"));

        e2.setDomain("other");
        assertNotEquals(e1, e2);
        e2.setDomain(null);
        assertNotEquals(e1, e2);
        e2.setDomain("sports");
        assertEquals(e1, e2);

        e2.setName("other");
        assertNotEquals(e1, e2);
        e2.setName(null);
        assertNotEquals(e1, e2);
        e2.setName("api");
        assertEquals(e1, e2);

        e2.setEngine("other");
        assertNotEquals(e1, e2);
        e2.setEngine(null);
        assertNotEquals(e1, e2);
        e2.setEngine("rego");
        assertEquals(e1, e2);

        e2.setVersion("v2");
        assertNotEquals(e1, e2);
        e2.setVersion(null);
        assertNotEquals(e1, e2);
        e2.setVersion("v1");
        assertEquals(e1, e2);

        e2.setRevision("200");
        assertNotEquals(e1, e2);
        e2.setRevision(null);
        assertNotEquals(e1, e2);
        e2.setRevision("100");
        assertEquals(e1, e2);

        Validator validator = new Validator(ZTSSchema.instance());
        assertTrue(validator.validate(e1, "PolicyBundleEntry").valid);
        assertFalse(validator.validate(entry().setRevision(null), "PolicyBundleEntry").valid);
    }

    @Test
    public void testPolicyBundleEntries() {

        List<PolicyBundleEntry> list = new ArrayList<>(Arrays.asList(entry()));
        PolicyBundleEntries l1 = new PolicyBundleEntries().setList(list);
        PolicyBundleEntries l2 = new PolicyBundleEntries().setList(new ArrayList<>(list));

        assertEquals(l1.getList(), list);
        assertEquals(l1, l1);
        assertEquals(l1, l2);
        assertFalse(l1.equals(null));
        assertFalse(l1.equals("string"));

        l2.setList(new ArrayList<>());
        assertNotEquals(l1, l2);
        l2.setList(null);
        assertNotEquals(l1, l2);
        l2.setList(new ArrayList<>(list));
        assertEquals(l1, l2);

        Validator validator = new Validator(ZTSSchema.instance());
        assertTrue(validator.validate(l1, "PolicyBundleEntries").valid);
        assertFalse(validator.validate(new PolicyBundleEntries(), "PolicyBundleEntries").valid);
    }
}

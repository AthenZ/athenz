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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class PolicyBundleTest {

    private PolicyBundleFile newFile() {
        return new PolicyBundleFile().setPath("authz.rego").setContent("package authz").setSha256("abcd");
    }

    private PolicyBundle newBundle() {
        return new PolicyBundle().setName("sports:bundle.api").setEngine("rego")
                .setFiles(Collections.singletonList(newFile()))
                .setRoots(Collections.singletonList("sports/api"))
                .setVersion("0").setActive(true).setDescription("test bundle")
                .setModified(Timestamp.fromMillis(100));
    }

    @Test
    public void testPolicyBundleFile() {

        PolicyBundleFile file1 = newFile();
        PolicyBundleFile file2 = newFile();

        assertEquals(file1, file2);
        assertEquals(file1, file1);
        assertNotEquals(null, file1);
        assertNotEquals("file", file1);

        assertEquals(file1.getPath(), "authz.rego");
        assertEquals(file1.getContent(), "package authz");
        assertEquals(file1.getSha256(), "abcd");

        file2.setPath("authz2.rego");
        assertNotEquals(file1, file2);
        file2.setPath(null);
        assertNotEquals(file1, file2);
        file2.setPath("authz.rego");
        assertEquals(file1, file2);

        file2.setContent("package authz2");
        assertNotEquals(file1, file2);
        file2.setContent(null);
        assertNotEquals(file1, file2);
        file2.setContent("package authz");
        assertEquals(file1, file2);

        file2.setSha256("1234");
        assertNotEquals(file1, file2);
        file2.setSha256(null);
        assertNotEquals(file1, file2);
        file2.setSha256("abcd");
        assertEquals(file1, file2);
    }

    @Test
    public void testPolicyBundle() {

        PolicyBundle bundle1 = newBundle();
        PolicyBundle bundle2 = newBundle();

        assertEquals(bundle1, bundle2);
        assertEquals(bundle1, bundle1);
        assertNotEquals(null, bundle1);
        assertNotEquals("bundle", bundle1);

        assertEquals(bundle1.getName(), "sports:bundle.api");
        assertEquals(bundle1.getEngine(), "rego");
        assertEquals(bundle1.getFiles(), Collections.singletonList(newFile()));
        assertEquals(bundle1.getRoots(), Collections.singletonList("sports/api"));
        assertEquals(bundle1.getVersion(), "0");
        assertTrue(bundle1.getActive());
        assertEquals(bundle1.getDescription(), "test bundle");
        assertEquals(bundle1.getModified(), Timestamp.fromMillis(100));

        bundle2.setName("sports:bundle.api2");
        assertNotEquals(bundle1, bundle2);
        bundle2.setName(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setName("sports:bundle.api");
        assertEquals(bundle1, bundle2);

        bundle2.setEngine("other");
        assertNotEquals(bundle1, bundle2);
        bundle2.setEngine(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setEngine("rego");
        assertEquals(bundle1, bundle2);

        bundle2.setFiles(Collections.emptyList());
        assertNotEquals(bundle1, bundle2);
        bundle2.setFiles(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setFiles(Collections.singletonList(newFile()));
        assertEquals(bundle1, bundle2);

        bundle2.setRoots(Collections.emptyList());
        assertNotEquals(bundle1, bundle2);
        bundle2.setRoots(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setRoots(Collections.singletonList("sports/api"));
        assertEquals(bundle1, bundle2);

        bundle2.setVersion("1");
        assertNotEquals(bundle1, bundle2);
        bundle2.setVersion(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setVersion("0");
        assertEquals(bundle1, bundle2);

        bundle2.setActive(false);
        assertNotEquals(bundle1, bundle2);
        bundle2.setActive(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setActive(true);
        assertEquals(bundle1, bundle2);

        bundle2.setDescription("bundle2");
        assertNotEquals(bundle1, bundle2);
        bundle2.setDescription(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setDescription("test bundle");
        assertEquals(bundle1, bundle2);

        bundle2.setModified(Timestamp.fromMillis(200));
        assertNotEquals(bundle1, bundle2);
        bundle2.setModified(null);
        assertNotEquals(bundle1, bundle2);
        bundle2.setModified(Timestamp.fromMillis(100));
        assertEquals(bundle1, bundle2);

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result result = validator.validate(bundle1, "PolicyBundle");
        assertTrue(result.valid, result.error);

        result = validator.validate(new PolicyBundle().setName("sports:bundle.api"), "PolicyBundle");
        assertFalse(result.valid);
    }

    @Test
    public void testPolicyBundles() {

        PolicyBundles bundles1 = new PolicyBundles().setList(Collections.singletonList(newBundle()));
        PolicyBundles bundles2 = new PolicyBundles().setList(Collections.singletonList(newBundle()));

        assertEquals(bundles1, bundles2);
        assertEquals(bundles1, bundles1);
        assertNotEquals(null, bundles1);
        assertNotEquals("bundles", bundles1);
        assertEquals(bundles1.getList(), Collections.singletonList(newBundle()));

        bundles2.setList(Collections.emptyList());
        assertNotEquals(bundles1, bundles2);
        bundles2.setList(null);
        assertNotEquals(bundles1, bundles2);
    }

    @Test
    public void testPolicyBundleList() {

        PolicyBundleList list1 = new PolicyBundleList().setNames(List.of("api", "backend"));
        PolicyBundleList list2 = new PolicyBundleList().setNames(List.of("api", "backend"));

        assertEquals(list1, list2);
        assertEquals(list1, list1);
        assertNotEquals(null, list1);
        assertNotEquals("list", list1);
        assertEquals(list1.getNames(), List.of("api", "backend"));

        list2.setNames(List.of("api"));
        assertNotEquals(list1, list2);
        list2.setNames(null);
        assertNotEquals(list1, list2);
    }

    @Test
    public void testPolicyBundleOptions() {

        PolicyBundleOptions opts1 = new PolicyBundleOptions().setVersion("1").setFromVersion("0");
        PolicyBundleOptions opts2 = new PolicyBundleOptions().setVersion("1").setFromVersion("0");

        assertEquals(opts1, opts2);
        assertEquals(opts1, opts1);
        assertNotEquals(null, opts1);
        assertNotEquals("opts", opts1);
        assertEquals(opts1.getVersion(), "1");
        assertEquals(opts1.getFromVersion(), "0");

        opts2.setVersion("2");
        assertNotEquals(opts1, opts2);
        opts2.setVersion(null);
        assertNotEquals(opts1, opts2);
        opts2.setVersion("1");
        assertEquals(opts1, opts2);

        opts2.setFromVersion("2");
        assertNotEquals(opts1, opts2);
        opts2.setFromVersion(null);
        assertNotEquals(opts1, opts2);
        opts2.setFromVersion("0");
        assertEquals(opts1, opts2);
    }
}

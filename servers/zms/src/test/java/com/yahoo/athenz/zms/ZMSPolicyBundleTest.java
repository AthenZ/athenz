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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.PolicyBundleValidator;
import com.yahoo.athenz.common.server.store.PolicyBundleValidatorFactory;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.utils.SignUtils;
import org.mockito.Mockito;
import org.testng.annotations.*;

import jakarta.ws.rs.core.Response;
import java.util.*;

import static org.testng.Assert.*;

public class ZMSPolicyBundleTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_ENABLED, "true");
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void shutDown() {
        System.clearProperty(ZMSConsts.ZMS_PROP_BUNDLE_ENABLED);
        System.clearProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(ZMSConsts.ZMS_PROP_QUOTA_BUNDLE);
        System.clearProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATION_MODE);
        zmsTestInitializer.shutDown();
    }

    public static class RejectingValidatorFactory implements PolicyBundleValidatorFactory {
        @Override
        public PolicyBundleValidator create() throws ServerResourceException {
            return (domainName, bundleName, bundle) -> {
                for (PolicyBundleFile file : bundle.getFiles()) {
                    if (file.getContent().contains("forbidden")) {
                        return "forbidden content in " + file.getPath();
                    }
                }
                return null;
            };
        }
    }

    private PolicyBundleFile file(String path, String content) {
        return new PolicyBundleFile().setPath(path).setContent(content);
    }

    private PolicyBundle regoBundle(String domainName, String bundleName, String version, String... modules) {
        List<PolicyBundleFile> files = new ArrayList<>();
        for (int i = 0; i < modules.length; i++) {
            files.add(file("mod" + i + ".rego", modules[i]));
        }
        return new PolicyBundle().setName(domainName + ":bundle." + bundleName).setEngine("rego")
                .setVersion(version).setFiles(files);
    }

    private void assertRequestFails(Runnable runnable, int code, String msg) {
        try {
            runnable.run();
            fail("expected failure: " + msg);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code, ex.getMessage());
            assertTrue(ex.getMessage().contains(msg), ex.getMessage());
        }
    }

    private Set<String> paths(PolicyBundle bundle) {
        Set<String> paths = new TreeSet<>();
        for (PolicyBundleFile file : bundle.getFiles()) {
            paths.add(file.getPath());
        }
        return paths;
    }

    private PolicyBundle putBundle(ZMSImpl zms, RsrcCtxWrapper ctx, String domainName, String bundleName,
            PolicyBundle bundle) {
        Response response = zms.putPolicyBundle(ctx, domainName, bundleName, zmsTestInitializer.getAuditRef(),
                Boolean.TRUE, bundle);
        return (PolicyBundle) response.getEntity();
    }

    @Test
    public void testPutBundleLifecycleAndReads() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-lifecycle";
        zmsTestInitializer.createTopLevelDomain(domainName);

        // unknown bundle and empty lists

        assertRequestFails(() -> zms.getPolicyBundle(ctx, domainName, "b1"), 404, "Bundle not found");
        assertRequestFails(() -> zms.getPolicyBundleVersion(ctx, domainName, "b1", "0"), 404, "Bundle not found");
        assertTrue(zms.getPolicyBundleList(ctx, domainName).getNames().isEmpty());
        assertTrue(zms.getPolicyBundles(ctx, domainName, null).getList().isEmpty());
        assertTrue(zms.getPolicyBundleVersionList(ctx, domainName, "b1").getNames().isEmpty());

        // create with mixed case values - engine, name and allowed services
        // are lower-cased. no version means version "0" and active

        PolicyBundle bundle = regoBundle(domainName, "B1", null, "package a", "package b")
                .setRoots(Collections.singletonList(domainName + "/authz"))
                .setDescription("test bundle");
        bundle.setName(domainName + ":bundle.B1").setEngine("REGO");
        PolicyBundle created = putBundle(zms, ctx, domainName, "B1", bundle);
        assertNotNull(created);
        assertEquals(created.getName(), domainName + ":bundle.b1");
        assertEquals(created.getEngine(), "rego");
        assertEquals(created.getVersion(), "0");
        assertEquals(created.getActive(), Boolean.TRUE);
        assertEquals(created.getRoots(), Collections.singletonList(domainName + "/authz"));
        assertEquals(created.getDescription(), "test bundle");
        assertEquals(created.getFiles().size(), 2);
        for (PolicyBundleFile f : created.getFiles()) {
            assertEquals(f.getSha256().length(), 64);
        }

        // returnObj false returns no object

        Response response = zms.putPolicyBundle(ctx, domainName, "b2", auditRef, Boolean.FALSE,
                regoBundle(domainName, "b2", null, "package c"));
        assertNull(response.getEntity());
        response = zms.putPolicyBundle(ctx, domainName, "b3", auditRef, null,
                regoBundle(domainName, "b3", null, "package c"));
        assertNull(response.getEntity());

        // reads

        PolicyBundle fetched = zms.getPolicyBundle(ctx, domainName, "B1");
        assertEquals(fetched.getVersion(), "0");
        assertEquals(paths(fetched), new TreeSet<>(Arrays.asList("mod0.rego", "mod1.rego")));
        assertEquals(zms.getPolicyBundleList(ctx, domainName).getNames(), Arrays.asList("b1", "b2", "b3"));
        assertEquals(zms.getPolicyBundles(ctx, domainName, false).getList().size(), 3);
        assertEquals(zms.getPolicyBundleVersionList(ctx, domainName, "b1").getNames(),
                Collections.singletonList("0"));
        assertEquals(zms.getPolicyBundleVersion(ctx, domainName, "b1", "0").getVersion(), "0");

        // update the active version without a version replaces its files

        PolicyBundle updated = putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", null, "package z"));
        assertEquals(updated.getVersion(), "0");
        assertEquals(updated.getActive(), Boolean.TRUE);
        assertEquals(paths(updated), Collections.singleton("mod0.rego"));
        assertNull(updated.getDescription());

        // invalid requests

        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false,
                regoBundle(domainName, "b1", null, "package z").setEngine("wasm")), 400, "unsupported bundle engine");
        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false,
                regoBundle(domainName, "other", null, "package z")), 400, "bundle name mismatch");
        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false,
                regoBundle(domainName, "b1", null)), 400, "at least one file");
        assertRequestFails(() -> zms.getPolicyBundle(ctx, "invalid domain!", "b1"), 400, "");
        assertRequestFails(() -> zms.getPolicyBundleVersion(ctx, domainName, "b1", "bad version!"), 400, "");

        // delete the bundle and make sure all versions are gone

        zms.deletePolicyBundle(ctx, domainName, "B1", auditRef);
        assertRequestFails(() -> zms.getPolicyBundle(ctx, domainName, "b1"), 404, "Bundle not found");
        assertRequestFails(() -> zms.deletePolicyBundle(ctx, domainName, "b1", auditRef), 404,
                "unable to delete bundle");

        // domain delete must also clean up remaining bundles

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testPutBundleWithVersions() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-versions";
        zmsTestInitializer.createTopLevelDomain(domainName);

        // version specified on an absent bundle: created active with that version

        PolicyBundle created = putBundle(zms, ctx, domainName, "b1",
                regoBundle(domainName, "b1", "V1", "package v1"));
        assertEquals(created.getVersion(), "v1");
        assertEquals(created.getActive(), Boolean.TRUE);

        // version specified on an existing bundle: non-active new version

        PolicyBundle v2 = putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "v2", "package v2"));
        assertEquals(v2.getVersion(), "v2");
        assertEquals(v2.getActive(), Boolean.FALSE);
        assertEquals(zms.getPolicyBundle(ctx, domainName, "b1").getVersion(), "v1");

        // update the existing non-active version keeps it non-active and replaces files

        v2 = putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "v2", "package v2a", "package v2b"));
        assertEquals(v2.getActive(), Boolean.FALSE);
        assertEquals(v2.getFiles().size(), 2);

        // update the active version explicitly by version

        PolicyBundle v1 = putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "v1", "package v1a"));
        assertEquals(v1.getActive(), Boolean.TRUE);
        assertEquals(v1.getFiles().size(), 1);

        // fill up to the max (5) versions

        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "v3", "package v3"));
        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "v4", "package v4"));
        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "v5", "package v5"));
        assertEquals(zms.getPolicyBundleVersionList(ctx, domainName, "b1").getNames().size(), 5);
        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false,
                regoBundle(domainName, "b1", "v6", "package v6")), 429, "max number of versions reached");
        assertRequestFails(() -> zms.putPolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("v6"), auditRef, false), 429, "max number of versions reached");

        // only the active version is returned by default - all with include non-active

        PolicyBundles bundles = zms.getPolicyBundles(ctx, domainName, false);
        assertEquals(bundles.getList().size(), 1);
        assertEquals(bundles.getList().get(0).getVersion(), "v1");
        bundles = zms.getPolicyBundles(ctx, domainName, true);
        assertEquals(bundles.getList().size(), 5);

        // delete the active version is rejected, non-active is fine

        assertRequestFails(() -> zms.deletePolicyBundleVersion(ctx, domainName, "b1", "V1", auditRef), 400,
                "unable to delete active bundle version");
        assertRequestFails(() -> zms.deletePolicyBundleVersion(ctx, domainName, "b1", "unknown", auditRef), 404,
                "unable to fetch bundle");
        zms.deletePolicyBundleVersion(ctx, domainName, "b1", "V5", auditRef);
        assertEquals(zms.getPolicyBundleVersionList(ctx, domainName, "b1").getNames().size(), 4);
        assertRequestFails(() -> zms.getPolicyBundleVersion(ctx, domainName, "b1", "v5"), 404, "Bundle not found");

        // brand-new bundle with no version on an existing bundle that has no active version
        // cannot happen through the api, but an unknown bundle with version works as above.

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testPutBundleVersionAndSetActive() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-copy";
        zmsTestInitializer.createTopLevelDomain(domainName);

        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", null, "package one", "package two"));

        // copy from the active version

        Response response = zms.putPolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("Copy1"), auditRef, Boolean.TRUE);
        PolicyBundle copy = (PolicyBundle) response.getEntity();
        assertEquals(copy.getVersion(), "copy1");
        assertEquals(copy.getActive(), Boolean.FALSE);
        assertEquals(copy.getFiles().size(), 2);

        // modify the copy and create another version from it

        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", "copy1", "package changed"));
        response = zms.putPolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("copy2").setFromVersion("COPY1"), auditRef, Boolean.FALSE);
        assertNull(response.getEntity());
        PolicyBundle copy2 = zms.getPolicyBundleVersion(ctx, domainName, "b1", "copy2");
        assertEquals(copy2.getFiles().size(), 1);
        assertEquals(copy2.getFiles().get(0).getContent(), "package changed");
        assertEquals(copy2.getActive(), Boolean.FALSE);

        // errors

        assertRequestFails(() -> zms.putPolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("copy2"), auditRef, false), 400, "already exists");
        assertRequestFails(() -> zms.putPolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("copy3").setFromVersion("nope"), auditRef, false),
                404, "unable to fetch bundle");

        // activate

        assertRequestFails(() -> zms.setActivePolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("nope"), auditRef), 404, "unable to fetch bundle");
        zms.setActivePolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("Copy2"), auditRef);
        PolicyBundle active = zms.getPolicyBundle(ctx, domainName, "b1");
        assertEquals(active.getVersion(), "copy2");
        assertEquals(active.getActive(), Boolean.TRUE);
        assertEquals(zms.getPolicyBundleVersion(ctx, domainName, "b1", "0").getActive(), Boolean.FALSE);

        // the previous active version can now be deleted but the new active cannot

        zms.deletePolicyBundleVersion(ctx, domainName, "b1", "0", auditRef);
        assertRequestFails(() -> zms.deletePolicyBundleVersion(ctx, domainName, "b1", "copy2", auditRef),
                400, "unable to delete active bundle version");

        // updating the active version without a version now updates copy2

        PolicyBundle updated = putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", null, "package n"));
        assertEquals(updated.getVersion(), "copy2");

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testPutBundleFile() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-file";
        zmsTestInitializer.createTopLevelDomain(domainName);

        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                file("x.rego", "package x")), 404, "unknown bundle");

        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", null, "package one"));

        // add a new file

        zms.putPolicyBundleFile(ctx, domainName, "B1", auditRef, file("sub/new.rego", "package new"));
        PolicyBundle bundle = zms.getPolicyBundle(ctx, domainName, "b1");
        assertEquals(paths(bundle), new TreeSet<>(Arrays.asList("mod0.rego", "sub/new.rego")));
        for (PolicyBundleFile f : bundle.getFiles()) {
            assertEquals(f.getSha256().length(), 64);
        }

        // replace an existing file

        zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef, file("mod0.rego", "package replaced"));
        bundle = zms.getPolicyBundle(ctx, domainName, "b1");
        assertEquals(bundle.getFiles().size(), 2);
        for (PolicyBundleFile f : bundle.getFiles()) {
            if (f.getPath().equals("mod0.rego")) {
                assertEquals(f.getContent(), "package replaced");
            }
        }

        // validation failures must not change the bundle

        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                file("notes.txt", "hello")), 400, "not supported for rego bundles");
        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                file("data.json", "{bad")), 400, "is not valid json");
        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                file("athenz/x.rego", "package x")), 400, "reserved directory");
        bundle = zms.getPolicyBundle(ctx, domainName, "b1");
        assertEquals(paths(bundle), new TreeSet<>(Arrays.asList("mod0.rego", "sub/new.rego")));

        // the file is only added to the active version

        zms.putPolicyBundleVersion(ctx, domainName, "b1", new PolicyBundleOptions().setVersion("v2"), auditRef, false);
        zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef, file("extra.rego", "package extra"));
        assertEquals(zms.getPolicyBundleVersion(ctx, domainName, "b1", "v2").getFiles().size(), 2);
        assertEquals(zms.getPolicyBundle(ctx, domainName, "b1").getFiles().size(), 3);

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testDeleteBundleFile() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-file-delete";
        zmsTestInitializer.createTopLevelDomain(domainName);

        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "mod0.rego", auditRef),
                404, "unknown bundle");

        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", null, "package one"));
        zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef, file("sub/new.rego", "package new"));

        // invalid and unknown paths

        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", null, auditRef),
                400, "invalid bundle file path");
        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "../x.rego", auditRef),
                400, "invalid bundle file path");
        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "other.rego", auditRef),
                404, "unknown bundle file");

        // delete one file - bundle name is case insensitive

        zms.deletePolicyBundleFile(ctx, domainName, "B1", "sub/new.rego", auditRef);
        PolicyBundle bundle = zms.getPolicyBundle(ctx, domainName, "b1");
        assertEquals(paths(bundle), new TreeSet<>(Collections.singletonList("mod0.rego")));

        // the last file cannot be removed

        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "mod0.rego", auditRef),
                400, "at least one file");
        assertEquals(zms.getPolicyBundle(ctx, domainName, "b1").getFiles().size(), 1);

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testReadOnlyMode() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-readonly";
        zmsTestInitializer.createTopLevelDomain(domainName);

        putBundle(zms, ctx, domainName, "b1", regoBundle(domainName, "b1", null, "package one"));

        DynamicConfigBoolean readOnly = Mockito.mock(DynamicConfigBoolean.class);
        Mockito.when(readOnly.get()).thenReturn(true);
        DynamicConfigBoolean saveMode = zms.readOnlyMode;
        zms.readOnlyMode = readOnly;
        final String msg = "Server in Maintenance Read-Only mode";
        try {
            assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false,
                    regoBundle(domainName, "b1", null, "package two")), 400, msg);
            assertRequestFails(() -> zms.deletePolicyBundle(ctx, domainName, "b1", auditRef), 400, msg);
            assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                    file("a.rego", "package a")), 400, msg);
            assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "a.rego", auditRef),
                    400, msg);
            assertRequestFails(() -> zms.putPolicyBundleVersion(ctx, domainName, "b1",
                    new PolicyBundleOptions().setVersion("v2"), auditRef, false), 400, msg);
            assertRequestFails(() -> zms.setActivePolicyBundleVersion(ctx, domainName, "b1",
                    new PolicyBundleOptions().setVersion("0"), auditRef), 400, msg);
            assertRequestFails(() -> zms.deletePolicyBundleVersion(ctx, domainName, "b1", "0", auditRef), 400, msg);

            // reads are still allowed

            assertNotNull(zms.getPolicyBundle(ctx, domainName, "b1"));
        } finally {
            zms.readOnlyMode = saveMode;
        }

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testAuditRefRequired() {

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_CHECK_OBJECTS,
                "role,group,policy,service,domain,entity,tenancy,template,bundle");
        ZMSImpl zms = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-audit";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        PolicyBundle bundle = regoBundle(domainName, "b1", null, "package one");
        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", null, false, bundle), 400,
                "Audit reference required");
        zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false, bundle);

        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", null,
                file("a.rego", "package a")), 400, "Audit reference required");
        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "mod0.rego", null),
                400, "Audit reference required");
        assertRequestFails(() -> zms.putPolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("v2"), null, false), 400, "Audit reference required");
        zms.putPolicyBundleVersion(ctx, domainName, "b1", new PolicyBundleOptions().setVersion("v2"), auditRef, false);
        assertRequestFails(() -> zms.setActivePolicyBundleVersion(ctx, domainName, "b1",
                new PolicyBundleOptions().setVersion("v2"), null), 400, "Audit reference required");
        assertRequestFails(() -> zms.deletePolicyBundleVersion(ctx, domainName, "b1", "v2", null), 400,
                "Audit reference required");
        assertRequestFails(() -> zms.deletePolicyBundle(ctx, domainName, "b1", null), 400,
                "Audit reference required");
        zms.deletePolicyBundle(ctx, domainName, "b1", auditRef);

        // a domain that does not exist

        assertRequestFails(() -> zms.putPolicyBundle(ctx, "no-such-domain", "b1", auditRef, false,
                regoBundle("no-such-domain", "b1", null, "package one")),
                404, "Unknown domain");

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testBundleQuota() {

        System.setProperty(ZMSConsts.ZMS_PROP_QUOTA_BUNDLE, "2");
        ZMSImpl zms = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-quota";
        zms.postTopLevelDomain(ctx, auditRef, null, zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser()));

        zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false, regoBundle(domainName, "b1", null, "package a"));
        zms.putPolicyBundle(ctx, domainName, "b2", auditRef, false, regoBundle(domainName, "b2", null, "package a"));
        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b3", auditRef, false,
                regoBundle(domainName, "b3", null, "package a")), 429, "bundle quota exceeded");

        // updates and new versions of existing bundles are not subject to the bundle count quota

        zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false, regoBundle(domainName, "b1", null, "package b"));
        zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false, regoBundle(domainName, "b1", "v2", "package b"));

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testContentValidator() {

        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATOR_FACTORY_CLASS,
                RejectingValidatorFactory.class.getName());
        ZMSImpl zms = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-validator";
        zms.postTopLevelDomain(ctx, auditRef, null, zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser()));

        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false,
                regoBundle(domainName, "b1", null, "package forbidden")), 400, "bundle validation failed: forbidden");
        zms.putPolicyBundle(ctx, domainName, "b1", auditRef, false, regoBundle(domainName, "b1", null, "package ok"));

        // the whole bundle is validated when a file is added and nothing is stored on failure

        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                file("bad.rego", "package forbidden")), 400, "forbidden content in bad.rego");
        assertEquals(zms.getPolicyBundle(ctx, domainName, "b1").getFiles().size(), 1);

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testLoadPolicyBundleValidator() {

        ZMSImpl zms = zmsTestInitializer.getZms();

        // no factory class - structural rules only

        System.clearProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATOR_FACTORY_CLASS);
        zms.loadPolicyBundleValidator();
        assertNotNull(zms.dbService.bundleRules);
        assertNull(zms.dbService.bundleRules.contentValidator);

        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATOR_FACTORY_CLASS,
                RejectingValidatorFactory.class.getName());
        zms.loadPolicyBundleValidator();
        assertNotNull(zms.dbService.bundleRules.contentValidator);

        System.setProperty(ZMSConsts.ZMS_PROP_BUNDLE_VALIDATOR_FACTORY_CLASS, "does.not.exist");
        try {
            zms.loadPolicyBundleValidator();
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid policy bundle validator factory class");
        }
    }

    @Test
    public void testPolicyBundleDisabledRejectsAllEndpoints() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "bundle-disabled";
        zmsTestInitializer.createTopLevelDomain(domainName);

        // the feature is opt-in and can be switched off at runtime

        DynamicConfigBoolean enabled = Mockito.mock(DynamicConfigBoolean.class);
        Mockito.when(enabled.get()).thenReturn(false);
        DynamicConfigBoolean saveEnabled = zms.policyBundleEnabled;
        zms.policyBundleEnabled = enabled;
        final String msg = "Policy bundle support is not enabled";
        PolicyBundle bundle = regoBundle(domainName, "b1", "0", "package a");
        PolicyBundleOptions options = new PolicyBundleOptions().setVersion("1");

        assertRequestFails(() -> zms.getPolicyBundleList(ctx, domainName), 400, msg);
        assertRequestFails(() -> zms.getPolicyBundles(ctx, domainName, null), 400, msg);
        assertRequestFails(() -> zms.getPolicyBundle(ctx, domainName, "b1"), 400, msg);
        assertRequestFails(() -> zms.putPolicyBundle(ctx, domainName, "b1", auditRef, Boolean.TRUE, bundle), 400, msg);
        assertRequestFails(() -> zms.deletePolicyBundle(ctx, domainName, "b1", auditRef), 400, msg);
        assertRequestFails(() -> zms.putPolicyBundleFile(ctx, domainName, "b1", auditRef,
                file("x.rego", "package x")), 400, msg);
        assertRequestFails(() -> zms.deletePolicyBundleFile(ctx, domainName, "b1", "x.rego", auditRef), 400, msg);
        assertRequestFails(() -> zms.getPolicyBundleVersionList(ctx, domainName, "b1"), 400, msg);
        assertRequestFails(() -> zms.getPolicyBundleVersion(ctx, domainName, "b1", "0"), 400, msg);
        assertRequestFails(() -> zms.putPolicyBundleVersion(ctx, domainName, "b1", options, auditRef,
                Boolean.TRUE), 400, msg);
        assertRequestFails(() -> zms.setActivePolicyBundleVersion(ctx, domainName, "b1", options, auditRef),
                400, msg);
        assertRequestFails(() -> zms.deletePolicyBundleVersion(ctx, domainName, "b1", "0", auditRef), 400, msg);

        // nothing was created while disabled and re-enabling takes effect right away

        Mockito.when(enabled.get()).thenReturn(true);
        assertTrue(zms.getPolicyBundleList(ctx, domainName).getNames().isEmpty());
        assertNotNull(putBundle(zms, ctx, domainName, "b1", bundle));
        zms.policyBundleEnabled = saveEnabled;
    }

    @Test
    public void testPolicyBundleDisabledByDefault() throws Exception {

        // restart the server without the property - the default is disabled (a mock-free read of the real flag)

        zmsTestInitializer.shutDown();
        System.clearProperty(ZMSConsts.ZMS_PROP_BUNDLE_ENABLED);
        zmsTestInitializer.setUp();

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        assertRequestFails(() -> zms.getPolicyBundleList(ctx, "sys.auth"), 400,
                "Policy bundle support is not enabled");
    }
}

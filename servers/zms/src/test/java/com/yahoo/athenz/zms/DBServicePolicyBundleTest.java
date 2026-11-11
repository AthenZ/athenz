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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.testng.Assert.*;

/**
 * Tests for the error and retry branches of the policy bundle operations in
 * DBService that cannot be reached with a real object store.
 */
public class DBServicePolicyBundleTest {

    private static final String DOMAIN = "bundledom";
    private static final String BUNDLE = "b1";
    private static final String AUDIT_REF = "audittest";

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @Mock private ObjectStore mockObjStore;
    @Mock private ObjectStoreConnection mockCon;

    private DBService dbService;
    private ObjectStore saveStore;
    private int saveRetryCount;
    private int saveSleepTime;

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
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.setUp();
        Mockito.reset(mockObjStore, mockCon);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockCon);

        dbService = zmsTestInitializer.getZms().dbService;
        saveStore = dbService.store;
        saveRetryCount = dbService.defaultRetryCount;
        saveSleepTime = dbService.retrySleepTime;
        dbService.store = mockObjStore;
        dbService.defaultRetryCount = 2;
        dbService.retrySleepTime = 1;
    }

    @AfterMethod
    public void shutDown() {
        dbService.store = saveStore;
        dbService.defaultRetryCount = saveRetryCount;
        dbService.retrySleepTime = saveSleepTime;
        zmsTestInitializer.shutDown();
    }

    private RsrcCtxWrapper ctx() {
        return zmsTestInitializer.getMockDomRsrcCtx();
    }

    private PolicyBundleFile file(String path) {
        return new PolicyBundleFile().setPath(path).setContent("package x").setSha256("abc");
    }

    private PolicyBundle bundle(String version, boolean active) {
        return new PolicyBundle().setName(DOMAIN + ":bundle." + BUNDLE).setEngine("rego")
                .setVersion(version).setActive(active)
                .setFiles(new ArrayList<>(Arrays.asList(file("a.rego"), file("b.rego"))));
    }

    private ServerResourceException serverError() {
        return new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, "sql error");
    }

    private ServerResourceException conflict() {
        return new ServerResourceException(ServerResourceException.CONFLICT, "db conflict");
    }

    private void assertError(Runnable runnable, int code, String msg) {
        try {
            runnable.run();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
            assertTrue(ex.getMessage().contains(msg), ex.getMessage());
        }
    }

    @Test
    public void testReadOperationsServerErrors() throws ServerResourceException {

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(serverError());
        Mockito.when(mockCon.getPolicyBundles(DOMAIN, true)).thenThrow(serverError());
        Mockito.when(mockCon.listPolicyBundles(DOMAIN)).thenThrow(serverError());
        Mockito.when(mockCon.listPolicyBundleVersions(DOMAIN, BUNDLE)).thenThrow(serverError());

        assertError(() -> dbService.getPolicyBundle(DOMAIN, BUNDLE, null), 500, "sql error");
        assertError(() -> dbService.getPolicyBundles(DOMAIN, true), 500, "sql error");
        assertError(() -> dbService.listPolicyBundles(DOMAIN), 500, "sql error");
        assertError(() -> dbService.listPolicyBundleVersions(DOMAIN, BUNDLE), 500, "sql error");
    }

    @Test
    public void testAuditLogPolicyBundle() {
        StringBuilder sb = new StringBuilder();
        dbService.auditLogPolicyBundle(sb, bundle("1", true).setFiles(null));
        assertTrue(sb.toString().contains("\"files\": []"));

        sb = new StringBuilder();
        dbService.auditLogPolicyBundle(sb, bundle("1", true));
        assertTrue(sb.toString().contains("{\"path\": \"a.rego\", \"sha256\": \"abc\"}, {\"path\": \"b.rego\""));
    }

    @Test
    public void testInsertPolicyBundleFilesFailure() throws ServerResourceException {
        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), eq("1"), any()))
                .thenReturn(true).thenReturn(false);
        assertFalse(dbService.insertPolicyBundleFiles(mockCon, DOMAIN, BUNDLE, "1",
                Arrays.asList(file("a.rego"), file("b.rego"))));
    }

    @Test
    public void testPutPolicyBundleFailures() throws ServerResourceException {

        // insert of a brand-new bundle fails

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(null);
        Mockito.when(mockCon.listPolicyBundleVersions(DOMAIN, BUNDLE)).thenReturn(Collections.emptyList());
        Mockito.when(mockCon.insertPolicyBundle(eq(DOMAIN), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundle(ctx(), DOMAIN, BUNDLE, bundle(null, false),
                AUDIT_REF, "putPolicyBundle", false), 500, "unable to put bundle");
        Mockito.verify(mockCon, Mockito.atLeastOnce()).rollbackChanges();

        // file insert fails

        Mockito.when(mockCon.insertPolicyBundle(eq(DOMAIN), any())).thenReturn(true);
        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), any(), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundle(ctx(), DOMAIN, BUNDLE, bundle(null, false),
                AUDIT_REF, "putPolicyBundle", false), 500, "unable to put bundle");

        // update of an existing version fails

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(bundle("3", true));
        Mockito.when(mockCon.updatePolicyBundle(eq(DOMAIN), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundle(ctx(), DOMAIN, BUNDLE, bundle(null, false),
                AUDIT_REF, "putPolicyBundle", false), 500, "unable to put bundle");
        Mockito.verify(mockCon, Mockito.never()).deletePolicyBundleFiles(any(), any(), any());

        // no active version and no version specified

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(null);
        Mockito.when(mockCon.listPolicyBundleVersions(DOMAIN, BUNDLE)).thenReturn(Collections.singletonList("1"));
        assertError(() -> dbService.executePutPolicyBundle(ctx(), DOMAIN, BUNDLE, bundle(null, false),
                AUDIT_REF, "putPolicyBundle", false), 400, "has no active version");
    }

    @Test
    public void testPutPolicyBundleRetry() throws ServerResourceException {

        // first attempt hits a conflict, the second one succeeds

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(conflict()).thenReturn(null);
        Mockito.when(mockCon.listPolicyBundleVersions(DOMAIN, BUNDLE)).thenReturn(Collections.emptyList());
        Mockito.when(mockCon.insertPolicyBundle(eq(DOMAIN), any())).thenReturn(true);
        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), any(), any())).thenReturn(true);

        PolicyBundle result = dbService.executePutPolicyBundle(ctx(), DOMAIN, BUNDLE, bundle(null, false),
                AUDIT_REF, "putPolicyBundle", false);
        assertNull(result);
        Mockito.verify(mockCon, Mockito.times(2)).getPolicyBundle(DOMAIN, BUNDLE, null);

        // non-retry errors are thrown immediately

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(serverError());
        assertError(() -> dbService.executePutPolicyBundle(ctx(), DOMAIN, BUNDLE, bundle(null, false),
                AUDIT_REF, "putPolicyBundle", false), 500, "sql error");
    }

    @Test
    public void testPutPolicyBundleFileFailures() throws ServerResourceException {

        Consumer<PolicyBundle> okValidator = b -> { };

        // unknown bundle

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(null);
        assertError(() -> dbService.executePutPolicyBundleFile(ctx(), DOMAIN, BUNDLE, file("c.rego"),
                AUDIT_REF, "putPolicyBundleFile", okValidator), 404, "unknown bundle");

        // validation failure rolls back and is propagated

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(bundle("1", true));
        Mockito.clearInvocations(mockCon);
        assertError(() -> dbService.executePutPolicyBundleFile(ctx(), DOMAIN, BUNDLE, file("c.rego"),
                AUDIT_REF, "putPolicyBundleFile", b -> {
                    throw ZMSUtils.requestError("bad bundle", "caller");
                }), 400, "bad bundle");
        Mockito.verify(mockCon, Mockito.times(1)).rollbackChanges();
        Mockito.verify(mockCon, Mockito.never()).insertPolicyBundleFile(any(), any(), any(), any());

        // file insert fails

        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), eq("1"), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundleFile(ctx(), DOMAIN, BUNDLE, file("c.rego"),
                AUDIT_REF, "putPolicyBundleFile", okValidator), 500, "unable to put bundle file");

        // bundle update fails

        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), eq("1"), any())).thenReturn(true);
        Mockito.when(mockCon.updatePolicyBundle(eq(DOMAIN), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundleFile(ctx(), DOMAIN, BUNDLE, file("c.rego"),
                AUDIT_REF, "putPolicyBundleFile", okValidator), 500, "unable to put bundle file");
    }

    @Test
    public void testPutPolicyBundleFileRetry() throws ServerResourceException {

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(conflict()).thenReturn(bundle("1", true));
        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), eq("1"), any())).thenReturn(true);
        Mockito.when(mockCon.updatePolicyBundle(eq(DOMAIN), any())).thenReturn(true);

        dbService.executePutPolicyBundleFile(ctx(), DOMAIN, BUNDLE, file("a.rego"),
                AUDIT_REF, "putPolicyBundleFile", b -> assertEquals(b.getFiles().size(), 2));
        Mockito.verify(mockCon, Mockito.times(2)).getPolicyBundle(DOMAIN, BUNDLE, null);

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(serverError());
        assertError(() -> dbService.executePutPolicyBundleFile(ctx(), DOMAIN, BUNDLE, file("a.rego"),
                AUDIT_REF, "putPolicyBundleFile", b -> { }), 500, "sql error");
    }

    @Test
    public void testDeletePolicyBundleFileFailures() throws ServerResourceException {

        Consumer<PolicyBundle> okValidator = b -> { };

        // unknown bundle

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(null);
        assertError(() -> dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "a.rego",
                AUDIT_REF, "deletePolicyBundleFile", okValidator), 404, "unknown bundle");

        // unknown file

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenAnswer(inv -> bundle("1", true));
        Mockito.clearInvocations(mockCon);
        assertError(() -> dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "c.rego",
                AUDIT_REF, "deletePolicyBundleFile", okValidator), 404, "unknown bundle file");
        Mockito.verify(mockCon, Mockito.times(1)).rollbackChanges();
        Mockito.verify(mockCon, Mockito.never()).deletePolicyBundleFile(any(), any(), any(), any());

        // validation failure rolls back and is propagated

        Mockito.clearInvocations(mockCon);
        assertError(() -> dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "a.rego",
                AUDIT_REF, "deletePolicyBundleFile", b -> {
                    throw ZMSUtils.requestError("bad bundle", "caller");
                }), 400, "bad bundle");
        Mockito.verify(mockCon, Mockito.times(1)).rollbackChanges();
        Mockito.verify(mockCon, Mockito.never()).deletePolicyBundleFile(any(), any(), any(), any());

        // file delete fails

        Mockito.when(mockCon.deletePolicyBundleFile(DOMAIN, BUNDLE, "1", "a.rego")).thenReturn(false);
        assertError(() -> dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "a.rego",
                AUDIT_REF, "deletePolicyBundleFile", okValidator), 500, "unable to delete bundle file");

        // bundle update fails

        Mockito.when(mockCon.deletePolicyBundleFile(DOMAIN, BUNDLE, "1", "a.rego")).thenReturn(true);
        Mockito.when(mockCon.updatePolicyBundle(eq(DOMAIN), any())).thenReturn(false);
        assertError(() -> dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "a.rego",
                AUDIT_REF, "deletePolicyBundleFile", okValidator), 500, "unable to delete bundle file");
    }

    @Test
    public void testDeletePolicyBundleFileRetry() throws ServerResourceException {

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(conflict()).thenReturn(bundle("1", true));
        Mockito.when(mockCon.deletePolicyBundleFile(DOMAIN, BUNDLE, "1", "a.rego")).thenReturn(true);
        Mockito.when(mockCon.updatePolicyBundle(eq(DOMAIN), any())).thenReturn(true);

        dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "a.rego",
                AUDIT_REF, "deletePolicyBundleFile", b -> assertEquals(b.getFiles().size(), 1));
        Mockito.verify(mockCon, Mockito.times(2)).getPolicyBundle(DOMAIN, BUNDLE, null);

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(serverError());
        assertError(() -> dbService.executeDeletePolicyBundleFile(ctx(), DOMAIN, BUNDLE, "a.rego",
                AUDIT_REF, "deletePolicyBundleFile", b -> { }), 500, "sql error");
    }

    @Test
    public void testDeletePolicyBundleFailures() throws ServerResourceException {

        Mockito.when(mockCon.deletePolicyBundle(DOMAIN, BUNDLE)).thenReturn(false);
        assertError(() -> dbService.executeDeletePolicyBundle(ctx(), DOMAIN, BUNDLE, AUDIT_REF, "deletePolicyBundle"),
                404, "unable to delete bundle");

        Mockito.when(mockCon.deletePolicyBundle(DOMAIN, BUNDLE)).thenThrow(conflict()).thenReturn(true);
        dbService.executeDeletePolicyBundle(ctx(), DOMAIN, BUNDLE, AUDIT_REF, "deletePolicyBundle");

        Mockito.when(mockCon.deletePolicyBundle(DOMAIN, BUNDLE)).thenThrow(serverError());
        assertError(() -> dbService.executeDeletePolicyBundle(ctx(), DOMAIN, BUNDLE, AUDIT_REF, "deletePolicyBundle"),
                500, "sql error");
    }

    @Test
    public void testPutPolicyBundleVersionFailures() throws ServerResourceException {

        Mockito.when(mockCon.listPolicyBundleVersions(DOMAIN, BUNDLE)).thenReturn(Collections.singletonList("1"));

        // source version not found

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, "9")).thenReturn(null);
        assertError(() -> dbService.executePutPolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2", "9",
                AUDIT_REF, "putPolicyBundleVersion", false), 404, "unable to fetch bundle");

        // insert of bundle fails

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenReturn(bundle("1", true));
        Mockito.when(mockCon.insertPolicyBundle(eq(DOMAIN), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2", null,
                AUDIT_REF, "putPolicyBundleVersion", false), 500, "unable to put bundle");

        // insert of files fails

        Mockito.when(mockCon.insertPolicyBundle(eq(DOMAIN), any())).thenReturn(true);
        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), eq("2"), any())).thenReturn(false);
        assertError(() -> dbService.executePutPolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2", null,
                AUDIT_REF, "putPolicyBundleVersion", false), 500, "unable to put bundle");

        // retry and then success

        Mockito.when(mockCon.insertPolicyBundleFile(eq(DOMAIN), eq(BUNDLE), eq("2"), any())).thenReturn(true);
        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(conflict())
                .thenReturn(bundle("1", true));
        assertNull(dbService.executePutPolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2", null,
                AUDIT_REF, "putPolicyBundleVersion", false));

        // non-retry error

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, null)).thenThrow(serverError());
        assertError(() -> dbService.executePutPolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2", null,
                AUDIT_REF, "putPolicyBundleVersion", false), 500, "sql error");
    }

    @Test
    public void testSetActivePolicyBundleVersionFailures() throws ServerResourceException {

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, "2")).thenReturn(null);
        assertError(() -> dbService.executeSetActivePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "setActivePolicyBundleVersion"), 404, "unable to fetch bundle");

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, "2")).thenReturn(bundle("2", false));
        Mockito.when(mockCon.setActivePolicyBundleVersion(DOMAIN, BUNDLE, "2")).thenReturn(false);
        assertError(() -> dbService.executeSetActivePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "setActivePolicyBundleVersion"), 500, "unable to set active bundle");

        Mockito.when(mockCon.setActivePolicyBundleVersion(DOMAIN, BUNDLE, "2")).thenThrow(conflict()).thenReturn(true);
        dbService.executeSetActivePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "setActivePolicyBundleVersion");

        Mockito.when(mockCon.setActivePolicyBundleVersion(DOMAIN, BUNDLE, "2")).thenThrow(serverError());
        assertError(() -> dbService.executeSetActivePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "setActivePolicyBundleVersion"), 500, "sql error");
    }

    @Test
    public void testDeletePolicyBundleVersionFailures() throws ServerResourceException {

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, "2")).thenReturn(null);
        assertError(() -> dbService.executeDeletePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "deletePolicyBundleVersion"), 404, "unable to fetch bundle");

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, "2")).thenReturn(bundle("2", true));
        assertError(() -> dbService.executeDeletePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "deletePolicyBundleVersion"), 400, "unable to delete active bundle version");

        Mockito.when(mockCon.getPolicyBundle(DOMAIN, BUNDLE, "2")).thenReturn(bundle("2", false));
        Mockito.when(mockCon.deletePolicyBundleVersion(DOMAIN, BUNDLE, "2")).thenReturn(false);
        assertError(() -> dbService.executeDeletePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "deletePolicyBundleVersion"), 404, "unable to delete bundle");

        Mockito.when(mockCon.deletePolicyBundleVersion(DOMAIN, BUNDLE, "2")).thenThrow(conflict()).thenReturn(true);
        dbService.executeDeletePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "deletePolicyBundleVersion");

        Mockito.when(mockCon.deletePolicyBundleVersion(DOMAIN, BUNDLE, "2")).thenThrow(serverError());
        assertError(() -> dbService.executeDeletePolicyBundleVersion(ctx(), DOMAIN, BUNDLE, "2",
                AUDIT_REF, "deletePolicyBundleVersion"), 500, "sql error");
    }
}

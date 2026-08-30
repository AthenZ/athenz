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

import com.yahoo.athenz.zms.config.SolutionTemplates;
import org.testng.annotations.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class SolutionTemplatesManagerTest {

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
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS, "1");
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void shutDown() {
        zmsTestInitializer.shutDown();
    }

    private static String solutionTemplatesJson(final String templateName, final int latestVersion) {
        return solutionTemplatesJson(templateName, latestVersion, "Dynamic template " + latestVersion);
    }

    private static String solutionTemplatesJson(final String templateName, final int latestVersion,
            final String description) {
        return "{"
                + "\"templates\": {"
                + "\"" + templateName + "\": {"
                + "\"metadata\": {"
                + "\"latestVersion\": " + latestVersion + ","
                + "\"timestamp\": \"2026-08-19T00:00:00.000Z\","
                + "\"description\": \"" + description + "\","
                + "\"keywordsToReplace\": \"\","
                + "\"autoUpdate\": false"
                + "}"
                + "}"
                + "}"
                + "}";
    }

    private static String invalidSolutionTemplatesJson() {
        return "{"
                + "\"templates\": {"
                + "\"invalid_template\": {"
                + "\"roles\": ["
                + "{"
                + "\"name\": \"test_role\","
                + "\"trust\": \"trusted.domain\","
                + "\"roleMembers\": ["
                + "{"
                + "\"memberName\": \"user.testuser\""
                + "}"
                + "]"
                + "}"
                + "]"
                + "}"
                + "}"
                + "}";
    }

    private static void writeSolutionTemplatesFile(final File file, final String contents) throws IOException {
        long modifiedMillis = Math.max(System.currentTimeMillis(), file.lastModified()) + TimeUnit.SECONDS.toMillis(2);
        writeSolutionTemplatesFile(file, contents, modifiedMillis);
    }

    private static void writeSolutionTemplatesFile(final File file, final String contents,
            final long modifiedMillis) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(contents);
        }
        java.nio.file.Files.setLastModifiedTime(file.toPath(), FileTime.fromMillis(modifiedMillis));
    }

    private static void restoreSystemProperty(final String propertyName, final String propertyValue) {
        if (propertyValue == null) {
            System.clearProperty(propertyName);
        } else {
            System.setProperty(propertyName, propertyValue);
        }
    }

    private static class ManualReloadZMSImpl extends ZMSImpl {

        @Override
        void initializeSolutionTemplatesReloadScheduler() {
        }
    }

    private static class FailingReadZMSImpl extends ManualReloadZMSImpl {

        // the flag must be static since instance field initializers do not
        // run until after the ZMSImpl constructor (which triggers our first
        // template read) has already completed

        static boolean failRead = false;

        @Override
        SolutionTemplatesManager newSolutionTemplatesManager() {
            return new SolutionTemplatesManager(jsonMapper, dynamicSolutionTemplatesReload, ZMSImpl::getRootDir,
                    this::updateSolutionTemplatesCompatibilityFields) {
                @Override
                SolutionTemplates readSolutionTemplates(Path path) throws IOException {
                    if (failRead) {
                        throw new IOException("transient read failure");
                    }
                    return super.readSolutionTemplates(path);
                }
            };
        }
    }

    private static class BackoffReadZMSImpl extends FailingReadZMSImpl {

        long currentMillis = TimeUnit.SECONDS.toMillis(100);
        int readCalls = 0;

        @Override
        SolutionTemplatesManager newSolutionTemplatesManager() {
            return new SolutionTemplatesManager(jsonMapper, dynamicSolutionTemplatesReload, ZMSImpl::getRootDir,
                    this::updateSolutionTemplatesCompatibilityFields) {
                @Override
                SolutionTemplates readSolutionTemplates(Path path) throws IOException {
                    readCalls++;
                    if (failRead) {
                        throw new IOException("transient read failure");
                    }
                    return super.readSolutionTemplates(path);
                }

                @Override
                long currentTimeMillis() {
                    return currentMillis;
                }
            };
        }
    }

    private static class ReloadTaskZMSImpl extends ZMSImpl {

        final Queue<SolutionTemplatesReloadStatus> reloadStatuses = new ArrayDeque<>();
        final List<Long> scheduledDelays = new ArrayList<>();
        boolean throwReloadException;

        @Override
        SolutionTemplatesManager newSolutionTemplatesManager() {
            return new SolutionTemplatesManager(jsonMapper, dynamicSolutionTemplatesReload, ZMSImpl::getRootDir,
                    this::updateSolutionTemplatesCompatibilityFields) {
                @Override
                SolutionTemplatesReloadStatus reloadSolutionTemplatesIfModified() {
                    if (throwReloadException) {
                        throw new RuntimeException("reload task failure");
                    }
                    return reloadStatuses.remove();
                }

                @Override
                void scheduleSolutionTemplatesReload(long delaySeconds) {
                    scheduledDelays.add(delaySeconds);
                }

                @Override
                long solutionTemplatesReloadFrequencySeconds() {
                    return 7;
                }

                @Override
                long solutionTemplatesReloadRetryDelaySeconds() {
                    return 3;
                }
            };
        }
    }

    private static SolutionTemplates solutionTemplates(final String templateName, final Template template) {
        SolutionTemplates solutionTemplates = new SolutionTemplates();
        HashMap<String, Template> templates = new HashMap<>();
        templates.put(templateName, template);
        solutionTemplates.setTemplates(templates);
        return solutionTemplates;
    }

    private static Template templateWithMetadata() {
        return new Template().setMetadata(new TemplateMetaData().setLatestVersion(1));
    }

    private static java.util.concurrent.atomic.AtomicReference<SolutionTemplatesSnapshot>
            solutionTemplatesSnapshotReference(final ZMSImpl zmsImpl) {

        return zmsImpl.solutionTemplatesManager().solutionTemplatesSnapshotReference();
    }

    private static java.util.concurrent.ScheduledExecutorService solutionTemplatesReloadExecutor(final ZMSImpl zmsImpl) {

        return zmsImpl.solutionTemplatesManager().solutionTemplatesReloadExecutor();
    }

    private static void setSolutionTemplatesReloadExecutor(final ZMSImpl zmsImpl,
            final java.util.concurrent.ScheduledExecutorService executor) {

        zmsImpl.solutionTemplatesManager().setSolutionTemplatesReloadExecutor(executor);
    }

    @Test
    public void testGetSolutionTemplatesSnapshotCreatesEmptySnapshotWhenUnset() throws ReflectiveOperationException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        java.util.concurrent.atomic.AtomicReference<SolutionTemplatesSnapshot> snapshots =
                solutionTemplatesSnapshotReference(zmsImpl);
        snapshots.set(null);

        SolutionTemplatesSnapshot snapshot = zmsImpl.getSolutionTemplatesSnapshot();
        assertTrue(snapshot.templates.getTemplates().isEmpty());
        assertTrue(snapshot.templateNames.isEmpty());
        assertNull(snapshot.path);
        assertEquals(snapshot.modifiedMillis, -1L);
        assertSame(zmsImpl.serverSolutionTemplates, snapshot.templates);
        assertSame(zmsImpl.getSolutionTemplatesSnapshot(), snapshot);
    }

    @Test
    public void testReadSolutionTemplatesEmptyDocuments() throws IOException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        File tempFile = File.createTempFile("dynamic_solution_templates_empty", ".json");
        try {
            // a valid json object document without any templates is empty

            writeSolutionTemplatesFile(tempFile, "{}");
            assertTrue(zmsImpl.solutionTemplatesManager().readSolutionTemplates(tempFile.toPath()).getTemplates().isEmpty());

            writeSolutionTemplatesFile(tempFile, "{\"templates\": {}}");
            assertTrue(zmsImpl.solutionTemplatesManager().readSolutionTemplates(tempFile.toPath()).getTemplates().isEmpty());
        } finally {
            tempFile.delete();
        }
    }

    @Test
    public void testReadSolutionTemplatesInvalidDocuments() throws IOException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        File tempFile = File.createTempFile("dynamic_solution_templates_invalid_doc", ".json");
        try {
            // corrupted json documents are rejected instead of being
            // treated as an empty template list

            final String[] invalidDocuments = {"null", "\"string\"", "5", "[{}]", "{invalid", ""};
            for (String invalidDocument : invalidDocuments) {
                writeSolutionTemplatesFile(tempFile, invalidDocument);
                try {
                    zmsImpl.solutionTemplatesManager().readSolutionTemplates(tempFile.toPath());
                    fail();
                } catch (RuntimeException ex) {
                    assertTrue(ex.getMessage().contains(tempFile.getName()));
                }
            }

            // structurally valid json objects with invalid content types
            // are rejected as well

            writeSolutionTemplatesFile(tempFile, "{\"templates\": \"invalid\"}");
            try {
                zmsImpl.solutionTemplatesManager().readSolutionTemplates(tempFile.toPath());
                fail();
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains("Invalid solution templates content"));
            }
        } finally {
            tempFile.delete();
        }
    }

    @Test
    public void testReadSolutionTemplatesCompatibleAllowsLegacyMetadata() throws IOException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        File tempFile = File.createTempFile("solution_templates_compatible", ".json");
        try {
            writeSolutionTemplatesFile(tempFile, "null");
            assertTrue(zmsImpl.solutionTemplatesManager().readSolutionTemplatesCompatible(tempFile.toPath()).getTemplates().isEmpty());

            writeSolutionTemplatesFile(tempFile, "{}");
            assertTrue(zmsImpl.solutionTemplatesManager().readSolutionTemplatesCompatible(tempFile.toPath()).getTemplates().isEmpty());

            writeSolutionTemplatesFile(tempFile, "{"
                    + "\"templates\": {"
                    + "\"legacy\": {"
                    + "\"roles\": ["
                    + "{"
                    + "\"name\": \"trusted_role\","
                    + "\"trust\": \"trusted.domain\""
                    + "}"
                    + "]"
                    + "}"
                    + "}"
                    + "}");

            SolutionTemplates solutionTemplates = zmsImpl.solutionTemplatesManager().readSolutionTemplatesCompatible(tempFile.toPath());
            assertTrue(solutionTemplates.contains("legacy"));
        } finally {
            tempFile.delete();
        }
    }

    @Test
    public void testReadSolutionTemplatesCompatibleRejectsInvalidLegacyRoles() throws IOException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        File tempFile = File.createTempFile("solution_templates_compatible_invalid", ".json");
        try {
            writeSolutionTemplatesFile(tempFile, invalidSolutionTemplatesJson());
            try {
                zmsImpl.solutionTemplatesManager().readSolutionTemplatesCompatible(tempFile.toPath());
                fail();
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains("has both trust and members defined"));
                assertTrue(ex.getMessage().contains("invalid_template"));
                assertTrue(ex.getMessage().contains("test_role"));
            }
        } finally {
            tempFile.delete();
        }
    }

    @Test
    public void testLoadSolutionTemplatesCorruptFileBlocksStartupWithDynamicReload()
            throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_corrupt", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsObj = new ManualReloadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsObj.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            // with dynamic reload enabled, a corrupted templates document
            // must not publish a new snapshot

            writeSolutionTemplatesFile(tempFile, "{corrupted");
            try {
                zmsObj.loadSolutionTemplates();
                fail();
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains(tempFile.getName()));
            }

            // the previous snapshot must be kept while the file is corrupt

            assertEquals(zmsObj.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);
            assertFalse(zmsObj.serverSolutionTemplates.contains("corrupted"));

            // once the file is fixed (updated modification time), the
            // background reload task picks up the recovered templates

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_recovered", 2));
            assertEquals(zmsObj.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsObj.getTemplate(ctx, "dynamic_recovered");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 2);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testLoadSolutionTemplatesCorruptFileKeepsDefaultStartupCompatibility()
            throws IOException {

        File tempFile = File.createTempFile("solution_templates_corrupt_compatible", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, "{corrupted");
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.clearProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);

            ZMSImpl zmsObj = new ZMSImpl();
            assertTrue(zmsObj.getSolutionTemplatesSnapshot().templates.getTemplates().isEmpty());
            assertTrue(zmsObj.serverSolutionTemplateNames.isEmpty());
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testValidateSolutionTemplatesConfigRejectsNullEntries() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // templates with no roles defined are allowed

        SolutionTemplates solutionTemplates = new SolutionTemplates();
        HashMap<String, Template> templates = new HashMap<>();
        templates.put("null_roles", templateWithMetadata());
        templates.put("valid_roles", templateWithMetadata().setRoles(Collections.singletonList(
                new Role().setName("trusted_role").setTrust("trusted.domain"))));
        solutionTemplates.setTemplates(templates);
        zmsImpl.solutionTemplatesManager().validateSolutionTemplatesConfig(solutionTemplates);

        // null template definitions are rejected

        SolutionTemplates nullTemplate = new SolutionTemplates();
        HashMap<String, Template> nullTemplates = new HashMap<>();
        nullTemplates.put("null_template", null);
        nullTemplate.setTemplates(nullTemplates);

        try {
            zmsImpl.solutionTemplatesManager().validateSolutionTemplatesConfig(nullTemplate);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("has a null definition"));
        }

        // null role entries are rejected

        SolutionTemplates nullRole = new SolutionTemplates();
        HashMap<String, Template> nullRoleTemplates = new HashMap<>();
        nullRoleTemplates.put("null_role", templateWithMetadata().setRoles(Arrays.asList(null,
                new Role().setName("trusted_role").setTrust("trusted.domain"))));
        nullRole.setTemplates(nullRoleTemplates);

        try {
            zmsImpl.solutionTemplatesManager().validateSolutionTemplatesConfig(nullRole);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("contains a null role"));
        }

        final Map<String, Template> invalidTemplates = new LinkedHashMap<>();
        invalidTemplates.put("null_metadata", new Template());
        invalidTemplates.put("null_policy", templateWithMetadata().setPolicies(Arrays.asList(null, new Policy())));
        invalidTemplates.put("null_group", templateWithMetadata().setGroups(Arrays.asList(null, new Group())));
        invalidTemplates.put("null_service", templateWithMetadata().setServices(Arrays.asList(null,
                new ServiceIdentity())));
        invalidTemplates.put("null_role_member", templateWithMetadata().setRoles(Collections.singletonList(
                new Role().setName("role").setRoleMembers(Arrays.asList(null, new RoleMember())))));
        invalidTemplates.put("null_policy_assertion", templateWithMetadata().setPolicies(Collections.singletonList(
                new Policy().setName("policy").setAssertions(Arrays.asList(null, new Assertion())))));
        invalidTemplates.put("null_group_member", templateWithMetadata().setGroups(Collections.singletonList(
                new Group().setName("group").setGroupMembers(Arrays.asList(null, new GroupMember())))));
        invalidTemplates.put("null_service_public_key", templateWithMetadata().setServices(Collections.singletonList(
                new ServiceIdentity().setName("service").setPublicKeys(Arrays.asList(null,
                        new PublicKeyEntry())))));

        for (Map.Entry<String, Template> invalidTemplate : invalidTemplates.entrySet()) {
            SolutionTemplates invalidSolutionTemplates = solutionTemplates(invalidTemplate.getKey(),
                    invalidTemplate.getValue());
            try {
                zmsImpl.solutionTemplatesManager().validateSolutionTemplatesConfig(invalidSolutionTemplates);
                fail();
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains(invalidTemplate.getKey()));
            }
        }
    }

    @Test
    public void testValidateSolutionTemplatesConfigAllowsMissingAndEmptyCollections() throws IOException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        File tempFile = File.createTempFile("solution_templates_optional_collections", ".json");
        try {
            writeSolutionTemplatesFile(tempFile, "{"
                    + "\"templates\": {"
                    + "\"metadata_only\": {"
                    + "\"metadata\": {\"latestVersion\": 1}"
                    + "},"
                    + "\"empty_collections\": {"
                    + "\"metadata\": {\"latestVersion\": 1},"
                    + "\"roles\": [],"
                    + "\"policies\": [],"
                    + "\"groups\": [],"
                    + "\"services\": []"
                    + "},"
                    + "\"valid_nested_collections\": {"
                    + "\"metadata\": {\"latestVersion\": 1},"
                    + "\"roles\": [{"
                    + "\"name\": \"_domain_:role.user\","
                    + "\"roleMembers\": [{\"memberName\": \"user.joe\"}]"
                    + "}],"
                    + "\"policies\": [{"
                    + "\"name\": \"_domain_:policy.user\","
                    + "\"assertions\": [{"
                    + "\"resource\": \"_domain_:resource\","
                    + "\"role\": \"_domain_:role.user\","
                    + "\"action\": \"read\""
                    + "}]"
                    + "}],"
                    + "\"groups\": [{"
                    + "\"name\": \"_domain_:group.test\","
                    + "\"groupMembers\": [{\"memberName\": \"user.jane\"}]"
                    + "}],"
                    + "\"services\": [{"
                    + "\"name\": \"_domain_.service\","
                    + "\"publicKeys\": [{\"id\": \"0\", \"key\": \"key\"}]"
                    + "}]"
                    + "}"
                    + "}"
                    + "}");

            SolutionTemplates solutionTemplates = zmsImpl.solutionTemplatesManager().readSolutionTemplates(tempFile.toPath());
            assertTrue(solutionTemplates.contains("metadata_only"));
            assertTrue(solutionTemplates.contains("empty_collections"));
            assertTrue(solutionTemplates.contains("valid_nested_collections"));
        } finally {
            tempFile.delete();
        }
    }

    @Test
    public void testSolutionTemplatesSnapshotPublishSameTimestampNoop() throws IOException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        Path path = Files.createTempFile("dynamic_solution_templates_snapshot", ".json");
        try {
            SolutionTemplates originalTemplates = solutionTemplates("snapshot_old", new Template());
            zmsImpl.solutionTemplatesManager().setServerSolutionTemplates(originalTemplates, path, 100L);
            SolutionTemplatesSnapshot originalSnapshot = zmsImpl.getSolutionTemplatesSnapshot();

            SolutionTemplates ignoredTemplates = solutionTemplates("snapshot_ignored", new Template());
            zmsImpl.solutionTemplatesManager().publishSolutionTemplatesSnapshot(
                    zmsImpl.solutionTemplatesManager().newSolutionTemplatesSnapshot(ignoredTemplates, path, 100L), false);

            assertSame(zmsImpl.getSolutionTemplatesSnapshot(), originalSnapshot);
            assertTrue(zmsImpl.serverSolutionTemplates.contains("snapshot_old"));
            assertFalse(zmsImpl.serverSolutionTemplates.contains("snapshot_ignored"));
            assertEquals(zmsImpl.serverSolutionTemplateNames, Collections.singletonList("snapshot_old"));
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    public void testLoadSolutionTemplatesMissingFileCreatesEmptySnapshot() throws IOException {

        Path tempDir = Files.createTempDirectory("dynamic_solution_templates_missing");
        Path missingPath = tempDir.resolve("missing.json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, missingPath.toString());
            System.clearProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);

            ZMSImpl zmsImpl = new ZMSImpl();
            SolutionTemplatesSnapshot snapshot = zmsImpl.getSolutionTemplatesSnapshot();
            assertTrue(snapshot.templates.getTemplates().isEmpty());
            assertEquals(snapshot.path, missingPath);
            assertEquals(snapshot.modifiedMillis, -1L);
            assertTrue(zmsImpl.serverSolutionTemplateNames.isEmpty());
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            Files.deleteIfExists(missingPath);
            Files.deleteIfExists(tempDir);
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadUsesConfiguredPathWhenSnapshotPathMissing()
            throws IOException, ReflectiveOperationException {

        File tempFile = File.createTempFile("dynamic_solution_templates_null_path", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_path", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsImpl = new ManualReloadZMSImpl();
            SolutionTemplatesSnapshot nullPathSnapshot = zmsImpl.solutionTemplatesManager().newSolutionTemplatesSnapshot(
                    zmsImpl.getSolutionTemplatesSnapshot().templates, null, -1L);
            solutionTemplatesSnapshotReference(zmsImpl).set(nullPathSnapshot);
            zmsImpl.updateSolutionTemplatesCompatibilityFields(nullPathSnapshot);

            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_path"));
            assertEquals(zmsImpl.getSolutionTemplatesSnapshot().path, tempFile.toPath());
            assertTrue(zmsImpl.dbService.zmsConfig.getServerSolutionTemplates().contains("dynamic_path"));
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadPostReadModifiedCheckFailureKeepsPreviousTemplates()
            throws IOException {

        class PostReadModifiedCheckFailZMSImpl extends ManualReloadZMSImpl {
            boolean failPostReadModifiedCheck;
            int modifiedCalls;

            @Override
            SolutionTemplatesManager newSolutionTemplatesManager() {
                return new SolutionTemplatesManager(jsonMapper, dynamicSolutionTemplatesReload, ZMSImpl::getRootDir,
                        this::updateSolutionTemplatesCompatibilityFields) {
                    @Override
                    long solutionTemplatesModifiedMillis(final Path path) throws IOException {
                        if (failPostReadModifiedCheck && ++modifiedCalls == 2) {
                            throw new IOException("post read modified check failure");
                        }
                        return super.solutionTemplatesModifiedMillis(path);
                    }
                };
            }
        }

        File tempFile = File.createTempFile("dynamic_solution_templates_post_read_check", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            PostReadModifiedCheckFailZMSImpl zmsImpl = new PostReadModifiedCheckFailZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_new", 2));
            zmsImpl.failPostReadModifiedCheck = true;
            zmsImpl.modifiedCalls = 0;

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_old"));
            assertFalse(zmsImpl.serverSolutionTemplates.contains("dynamic_new"));
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadSkipsPublishWhenFileChangesDuringRead()
            throws IOException {

        class ModifiedDuringReadZMSImpl extends ManualReloadZMSImpl {
            boolean updateDuringRead;
            File file;

            @Override
            SolutionTemplatesManager newSolutionTemplatesManager() {
                return new SolutionTemplatesManager(jsonMapper, dynamicSolutionTemplatesReload, ZMSImpl::getRootDir,
                        this::updateSolutionTemplatesCompatibilityFields) {
                    @Override
                    SolutionTemplates readSolutionTemplates(final Path path) throws IOException {
                        SolutionTemplates solutionTemplates = super.readSolutionTemplates(path);
                        if (updateDuringRead) {
                            updateDuringRead = false;
                            writeSolutionTemplatesFile(file, solutionTemplatesJson("dynamic_final", 3));
                        }
                        return solutionTemplates;
                    }
                };
            }
        }

        File tempFile = File.createTempFile("dynamic_solution_templates_changed_during_read", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ModifiedDuringReadZMSImpl zmsImpl = new ModifiedDuringReadZMSImpl();
            zmsImpl.file = tempFile;
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_new", 2));
            zmsImpl.updateDuringRead = true;

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            try {
                zmsImpl.getTemplate(ctx, "dynamic_new");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            assertTrue(zmsImpl.serverSolutionTemplates.contains("dynamic_old"));
            assertFalse(zmsImpl.serverSolutionTemplates.contains("dynamic_new"));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_final");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 3);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadDisabledByDefault() throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_disabled", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.clearProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);

            ZMSImpl zmsImpl = new ZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_new", 2));

            try {
                zmsImpl.getTemplate(ctx, "dynamic_new");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadEnabled() throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_enabled", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsImpl = new ManualReloadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_new", 2));

            try {
                zmsImpl.getTemplate(ctx, "dynamic_new");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_old"));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_new");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 2);
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_new"));
            assertTrue(zmsImpl.dbService.zmsConfig.getServerSolutionTemplates().contains("dynamic_new"));
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadSchedulerStartsWhenEnabled()
            throws IOException, ReflectiveOperationException {

        File tempFile = File.createTempFile("dynamic_solution_templates_scheduler", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        String originalFrequency = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS);
        ZMSImpl zmsImpl = null;
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_scheduler", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, "60");

            zmsImpl = new ZMSImpl();
            assertNotNull(solutionTemplatesReloadExecutor(zmsImpl));
            assertFalse(solutionTemplatesReloadExecutor(zmsImpl).isShutdown());
        } finally {
            if (zmsImpl != null) {
                zmsImpl.shutdownSolutionTemplatesReloadScheduler();
            }
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            tempFile.delete();
        }
    }

    @Test
    public void testSolutionTemplatesReloadTaskSchedulesNextRun() {

        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            System.clearProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
            ReloadTaskZMSImpl zmsImpl = new ReloadTaskZMSImpl();

            zmsImpl.reloadStatuses.add(SolutionTemplatesReloadStatus.FAILED);
            zmsImpl.solutionTemplatesManager().runSolutionTemplatesReloadTask();

            zmsImpl.reloadStatuses.add(SolutionTemplatesReloadStatus.RELOADED);
            zmsImpl.solutionTemplatesManager().runSolutionTemplatesReloadTask();

            zmsImpl.throwReloadException = true;
            zmsImpl.solutionTemplatesManager().runSolutionTemplatesReloadTask();

            assertEquals(zmsImpl.scheduledDelays, Arrays.asList(3L, 7L, 7L));
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
        }
    }

    @Test
    public void testSolutionTemplatesReloadBackoffCalculations() {

        String originalFrequency = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS);
        String originalMaxBackoff = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, "5");
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS, "20");
            BackoffReadZMSImpl zmsImpl = new BackoffReadZMSImpl();
            Path path = Paths.get("solution_templates.json");

            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadDelaySeconds(
                    SolutionTemplatesReloadStatus.RELOADED), 5);
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryDelaySeconds(), 5);

            zmsImpl.solutionTemplatesManager().recordSolutionTemplatesReloadFailure(path, 10L);
            assertTrue(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryPending(path, 10L));
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryPending(path, 11L));
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryDelaySeconds(), 5);
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadDelaySeconds(
                    SolutionTemplatesReloadStatus.FAILED), 5);

            zmsImpl.currentMillis += TimeUnit.SECONDS.toMillis(3);
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryDelaySeconds(), 2);

            zmsImpl.currentMillis += TimeUnit.SECONDS.toMillis(2);
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryDelaySeconds(), 0);
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryPending(path, 10L));

            zmsImpl.solutionTemplatesManager().recordSolutionTemplatesReloadFailure(path, 10L);
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryDelaySeconds(), 10);
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadNextBackoffSeconds(11), 20);

            zmsImpl.solutionTemplatesManager().clearSolutionTemplatesReloadFailure();
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryPending(path, 10L));
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadRetryDelaySeconds(), 5);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS, originalMaxBackoff);
        }
    }

    @Test
    public void testScheduleSolutionTemplatesReloadSkipsMissingOrShutdownExecutor()
            throws ReflectiveOperationException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        zmsImpl.solutionTemplatesManager().scheduleSolutionTemplatesReload(0);

        java.util.concurrent.ScheduledExecutorService executor =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        executor.shutdownNow();
        setSolutionTemplatesReloadExecutor(zmsImpl, executor);

        zmsImpl.solutionTemplatesManager().scheduleSolutionTemplatesReload(0);
        assertTrue(executor.isShutdown());
    }

    @Test
    public void testScheduleSolutionTemplatesReloadHandlesRejectedExecutor()
            throws ReflectiveOperationException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        java.util.concurrent.ScheduledExecutorService executor =
                mock(java.util.concurrent.ScheduledExecutorService.class);
        when(executor.isShutdown()).thenReturn(false);
        when(executor.schedule(any(Runnable.class), eq(5L), eq(TimeUnit.SECONDS)))
                .thenThrow(new java.util.concurrent.RejectedExecutionException("queue full"));
        setSolutionTemplatesReloadExecutor(zmsImpl, executor);

        zmsImpl.solutionTemplatesManager().scheduleSolutionTemplatesReload(5);

        verify(executor).schedule(any(Runnable.class), eq(5L), eq(TimeUnit.SECONDS));
    }

    @Test
    public void testSolutionTemplatesReloadHelperDefaults() {

        String originalFrequency = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS);
        String originalMaxBackoff = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS);
        try {
            ZMSImpl zmsImpl = zmsTestInitializer.getZms();

            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, "0");
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadFrequencySeconds(),
                    Long.parseLong(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS_DEFAULT));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, "6");
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS, "1");
            assertEquals(zmsImpl.solutionTemplatesManager().solutionTemplatesReloadMaxBackoffSeconds(), 6);
            assertTrue(zmsImpl.solutionTemplatesManager().currentTimeMillis() > 0);

            assertTrue(zmsImpl.solutionTemplatesManager().solutionTemplatesEmpty(null));
            assertTrue(zmsImpl.solutionTemplatesManager().solutionTemplatesEmpty(new SolutionTemplates()));
            SolutionTemplates emptyTemplates = new SolutionTemplates();
            emptyTemplates.setTemplates(new HashMap<>());
            assertTrue(zmsImpl.solutionTemplatesManager().solutionTemplatesEmpty(emptyTemplates));
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplatesEmpty(solutionTemplates("template", templateWithMetadata())));
            assertNull(zmsImpl.solutionTemplatesManager().solutionTemplateLatestVersion(null));
            assertNull(zmsImpl.solutionTemplatesManager().solutionTemplateLatestVersion(new Template()));
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplateLatestVersionIncremented(null, 2));
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplateLatestVersionIncremented(2, null));
            assertFalse(zmsImpl.solutionTemplatesManager().solutionTemplateLatestVersionIncremented(2, 2));
            assertTrue(zmsImpl.solutionTemplatesManager().solutionTemplateLatestVersionIncremented(2, 3));

            Template template = templateWithMetadata();
            zmsImpl.solutionTemplatesManager().validateSolutionTemplateReloadVersions(null, solutionTemplates("template", template));
            zmsImpl.solutionTemplatesManager().validateSolutionTemplateReloadVersion("new_template", null, template);
            zmsImpl.solutionTemplatesManager().validateSolutionTemplateReloadVersion("same_template", template, template);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS, originalMaxBackoff);
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadRejectsChangedTemplateWithoutVersionIncrement() throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_same_version", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_template", 1,
                    "original template"));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsImpl = new ManualReloadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_template").getMetadata().getDescription(),
                    "original template");

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_template", 1,
                    "changed without version increment"));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_template");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 1);
            assertEquals(template.getMetadata().getDescription(), "original template");
            assertEquals(zmsImpl.dbService.zmsConfig.getServerSolutionTemplates().get("dynamic_template")
                    .getMetadata().getDescription(), "original template");

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_template", 2,
                    "changed with version increment"));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            template = zmsImpl.getTemplate(ctx, "dynamic_template");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 2);
            assertEquals(template.getMetadata().getDescription(), "changed with version increment");
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadOlderModifiedTime() throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_older_mtime", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            long initialModifiedMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(20);
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_current", 1),
                    initialModifiedMillis);
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsImpl = new ManualReloadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_current").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_rollback", 2),
                    initialModifiedMillis - TimeUnit.SECONDS.toMillis(10));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_rollback");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 2);
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_rollback"));
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadMissingFileKeepsPreviousTemplates() throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_missing_file", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsImpl = new ManualReloadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            Files.deleteIfExists(tempFile.toPath());

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            ServerTemplateList templateList = zmsImpl.getServerTemplateList(ctx);
            assertTrue(templateList.getTemplateNames().contains("dynamic_old"));
            assertTrue(zmsImpl.dbService.zmsConfig.getServerSolutionTemplates().contains("dynamic_old"));
            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RETRY_PENDING);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            Files.deleteIfExists(tempFile.toPath());
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadInvalidKeepsPreviousTemplates() throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_invalid", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            ZMSImpl zmsImpl = new ManualReloadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, invalidSolutionTemplatesJson());

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);
            try {
                zmsImpl.getTemplate(ctx, "invalid_template");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            assertTrue(zmsImpl.dbService.zmsConfig.getServerSolutionTemplates().contains("dynamic_old"));

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_recovered", 3));
            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_recovered");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 3);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadSkipsDeterministicFailureAtSameTimestamp()
            throws IOException {

        class DeterministicFailureZMSImpl extends ManualReloadZMSImpl {
            boolean failReload;
            int readCalls;

            @Override
            SolutionTemplatesManager newSolutionTemplatesManager() {
                return new SolutionTemplatesManager(jsonMapper, dynamicSolutionTemplatesReload, ZMSImpl::getRootDir,
                        this::updateSolutionTemplatesCompatibilityFields) {
                    @Override
                    SolutionTemplates readSolutionTemplates(final Path path) throws IOException {
                        readCalls++;
                        if (failReload) {
                            throw new RuntimeException("deterministic reload failure");
                        }
                        return super.readSolutionTemplates(path);
                    }
                };
            }
        }

        File tempFile = File.createTempFile("dynamic_solution_templates_failed_mtime", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            DeterministicFailureZMSImpl zmsImpl = new DeterministicFailureZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_new", 2));
            zmsImpl.failReload = true;
            zmsImpl.readCalls = 0;

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_old"));
            assertEquals(zmsImpl.readCalls, 1);
            assertFalse(zmsImpl.serverSolutionTemplates.contains("dynamic_new"));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RETRY_PENDING);
            assertTrue(zmsImpl.getServerTemplateList(ctx).getTemplateNames().contains("dynamic_old"));
            assertEquals(zmsImpl.readCalls, 1);
            assertFalse(zmsImpl.serverSolutionTemplates.contains("dynamic_new"));

            zmsImpl.failReload = false;
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_recovered", 3));

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_recovered");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 3);
            assertEquals(zmsImpl.readCalls, 2);
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadAfterStartupReadFailure()
            throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_read_failure", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_recovered", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");

            FailingReadZMSImpl.failRead = true;
            FailingReadZMSImpl zmsImpl = new FailingReadZMSImpl();

            // since our startup load failed, the empty fallback snapshot must
            // not be tagged with the file timestamp so a reload is not skipped

            SolutionTemplatesSnapshot snapshot = zmsImpl.getSolutionTemplatesSnapshot();
            assertTrue(snapshot.templates.getTemplates().isEmpty());
            assertEquals(snapshot.path, tempFile.toPath());
            assertEquals(snapshot.modifiedMillis, -1L);

            // once reads succeed again, the background reload task must pick
            // up the templates without any file change

            FailingReadZMSImpl.failRead = false;
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_recovered");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 1);
            assertEquals(zmsImpl.getSolutionTemplatesSnapshot().modifiedMillis,
                    java.nio.file.Files.getLastModifiedTime(tempFile.toPath()).toMillis());
        } finally {
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            tempFile.delete();
        }
    }

    @Test
    public void testDynamicSolutionTemplatesReloadRetriesReadFailureAtSameTimestampAfterBackoff()
            throws IOException {

        File tempFile = File.createTempFile("dynamic_solution_templates_reload_read_failure", ".json");
        String originalTemplateFile = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME);
        String originalDynamicReload = System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD);
        String originalFrequency = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS);
        String originalMaxBackoff = System.getProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS);
        try {
            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_old", 1));
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, tempFile.getAbsolutePath());
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, "true");
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, "1");
            System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS, "4");

            FailingReadZMSImpl.failRead = false;
            BackoffReadZMSImpl zmsImpl = new BackoffReadZMSImpl();
            RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
            assertEquals(zmsImpl.getTemplate(ctx, "dynamic_old").getMetadata().getLatestVersion().intValue(), 1);

            writeSolutionTemplatesFile(tempFile, solutionTemplatesJson("dynamic_new", 2));
            FailingReadZMSImpl.failRead = true;
            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(), SolutionTemplatesReloadStatus.FAILED);
            int readCalls = zmsImpl.readCalls;

            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RETRY_PENDING);
            assertEquals(zmsImpl.readCalls, readCalls);

            FailingReadZMSImpl.failRead = false;
            try {
                zmsImpl.getTemplate(ctx, "dynamic_new");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            assertEquals(zmsImpl.readCalls, readCalls);

            zmsImpl.currentMillis += TimeUnit.SECONDS.toMillis(1);
            assertEquals(zmsImpl.solutionTemplatesManager().reloadSolutionTemplatesIfModified(),
                    SolutionTemplatesReloadStatus.RELOADED);
            Template template = zmsImpl.getTemplate(ctx, "dynamic_new");
            assertEquals(template.getMetadata().getLatestVersion().intValue(), 2);
        } finally {
            FailingReadZMSImpl.failRead = false;
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, originalTemplateFile);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_DYNAMIC_RELOAD, originalDynamicReload);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            restoreSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS, originalMaxBackoff);
            tempFile.delete();
        }
    }

}

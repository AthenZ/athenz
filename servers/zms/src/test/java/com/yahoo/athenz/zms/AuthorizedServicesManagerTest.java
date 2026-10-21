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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.zms.config.AuthorizedServices;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.AuthorizedServicesManager.ReloadStatus.*;
import static org.testng.Assert.*;

public class AuthorizedServicesManagerTest {

    private static final String FIRST_SERVICES = "{\"services\":{\"example.first\":{"
            + "\"allowedOperations\":[{\"name\":\"putrole\"}]}}}";
    private static final String SECOND_SERVICES = "{\"services\":{\"example.second\":{"
            + "\"allowedOperations\":[{\"name\":\"putpolicy\"}]}}}";

    private static class ManualTimeManager extends AuthorizedServicesManager {

        long nowMillis = TimeUnit.SECONDS.toMillis(100);
        final List<Long> scheduledDelays = new ArrayList<>();

        ManualTimeManager() {
            super(new ObjectMapper(), true, () -> ".");
        }

        @Override
        long currentTimeMillis() {
            return nowMillis;
        }

        @Override
        void scheduleReload(long delaySeconds) {
            scheduledDelays.add(delaySeconds);
        }
    }

    private AuthorizedServicesManager manager(boolean dynamicReload) {
        return new AuthorizedServicesManager(new ObjectMapper(), dynamicReload, () -> ".");
    }

    private static void write(Path path, String contents, long modifiedMillis) throws IOException {
        Files.writeString(path, contents, StandardCharsets.UTF_8);
        Files.setLastModifiedTime(path, FileTime.fromMillis(modifiedMillis));
    }

    private static void restoreProperty(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }

    @Test
    public void testDynamicReloadAndFailedUpdates() throws Exception {
        Path path = Files.createTempFile("authorized-services-reload", ".json");
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        long modifiedMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(2);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, path.toString());
            write(path, FIRST_SERVICES, modifiedMillis);
            AuthorizedServicesManager manager = manager(true);
            manager.loadAuthorizedServices();
            assertTrue(manager.getAuthorizedServices().contains("example.first"));
            assertEquals(manager.reloadIfModified(), NOT_MODIFIED);

            ZMSImpl zms = Mockito.mock(ZMSImpl.class, Mockito.CALLS_REAL_METHODS);
            zms.authorizedServicesManager = manager;
            zms.verifyAuthorizedServiceOperation("example.first", "putrole");

            write(path, SECOND_SERVICES, modifiedMillis += 2000);
            assertEquals(manager.reloadIfModified(), RELOADED);
            AuthorizedServices lastGood = manager.getAuthorizedServices();
            assertFalse(lastGood.contains("example.first"));
            assertTrue(lastGood.contains("example.second"));
            zms.verifyAuthorizedServiceOperation("example.second", "putpolicy");
            try {
                zms.verifyAuthorizedServiceOperation("example.first", "putrole");
                fail("Removed service must no longer be authorized");
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 403);
            }

            String[] invalidDocuments = {
                    "{invalid",
                    "{}",
                    "{\"services\":{\"example.invalid\":null}}",
                    "{\"services\":{\"example.invalid\":{\"allowedOperations\":[null]}}}",
                    "{\"services\":{\"example.invalid\":{\"allowedOperations\":[{\"name\":\"\"}]}}}",
                    "{\"services\":{\"example.invalid\":{\"allowedOperations\":[{\"name\":\"putrole\","
                            + "\"items\":{\"role-prefix\":[\"\"]}}]}}}",
                    "{\"services\":{}} " + FIRST_SERVICES,
                    FIRST_SERVICES + " {invalid"
            };
            for (String invalidDocument : invalidDocuments) {
                write(path, invalidDocument, modifiedMillis += 2000);
                assertEquals(manager.reloadIfModified(), FAILED);
                assertSame(manager.getAuthorizedServices(), lastGood);
                assertEquals(manager.reloadIfModified(), RETRY_PENDING);
            }

            write(path, "{\"services\":{}}", modifiedMillis + 2000);
            assertEquals(manager.reloadIfModified(), RELOADED);
            assertTrue(manager.getAuthorizedServices().getServices().isEmpty());
        } finally {
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
            Files.deleteIfExists(path);
        }
    }

    @Test
    public void testDisabledKeepsStartupList() throws Exception {
        Path path = Files.createTempFile("authorized-services-static", ".json");
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        long modifiedMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(2);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, path.toString());
            write(path, FIRST_SERVICES, modifiedMillis);
            AuthorizedServicesManager manager = manager(false);
            manager.loadAuthorizedServices();
            write(path, SECOND_SERVICES, modifiedMillis + 2000);
            assertEquals(manager.reloadIfModified(), DISABLED);
            assertTrue(manager.getAuthorizedServices().contains("example.first"));
            assertFalse(manager.getAuthorizedServices().contains("example.second"));
        } finally {
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
            Files.deleteIfExists(path);
        }
    }

    @Test
    public void testExistingConfigurationLoadsWithDynamicReload() {
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                    "src/test/resources/authorized_services.json");
            AuthorizedServicesManager manager = manager(true);
            manager.loadAuthorizedServices();
            assertTrue(manager.getAuthorizedServices().contains("coretech.storage"));
            assertEquals(manager.reloadIfModified(), NOT_MODIFIED);
        } finally {
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
        }
    }

    @Test
    public void testMissingAtStartupCanRecover() throws Exception {
        Path directory = Files.createTempDirectory("authorized-services-missing");
        Path path = directory.resolve("authorized_services.json");
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, path.toString());
            AuthorizedServicesManager manager = manager(true);
            manager.loadAuthorizedServices();
            assertTrue(manager.getAuthorizedServices().getServices().isEmpty());
            assertEquals(manager.reloadIfModified(), FAILED);

            write(path, FIRST_SERVICES, System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(2));
            assertEquals(manager.reloadIfModified(), RELOADED);
            assertTrue(manager.getAuthorizedServices().contains("example.first"));
        } finally {
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
            Files.deleteIfExists(path);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void testRetryBackoffAndResetAfterSuccess() throws Exception {
        Path path = Files.createTempFile("authorized-services-backoff", ".json");
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        String originalFrequency = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS);
        String originalMaxBackoff = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS);
        long modifiedMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(2);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, path.toString());
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS, "2");
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS, "5");
            write(path, FIRST_SERVICES, modifiedMillis);
            ManualTimeManager manager = new ManualTimeManager();
            manager.loadAuthorizedServices();
            AuthorizedServices lastGood = manager.getAuthorizedServices();

            write(path, "{invalid", modifiedMillis += 2000);
            assertEquals(manager.reloadIfModified(), FAILED); // retry after 2 seconds
            assertSame(manager.getAuthorizedServices(), lastGood);
            manager.nowMillis += 1999;
            assertEquals(manager.reloadIfModified(), RETRY_PENDING);
            manager.nowMillis++;
            assertEquals(manager.reloadIfModified(), FAILED); // retry after 4 seconds
            assertSame(manager.getAuthorizedServices(), lastGood);
            manager.nowMillis += 3999;
            assertEquals(manager.reloadIfModified(), RETRY_PENDING);
            manager.nowMillis++;
            assertEquals(manager.reloadIfModified(), FAILED); // retry after 5 seconds
            assertSame(manager.getAuthorizedServices(), lastGood);
            manager.nowMillis += 4999;
            assertEquals(manager.reloadIfModified(), RETRY_PENDING);
            manager.nowMillis++;
            assertEquals(manager.reloadIfModified(), FAILED); // capped at 5 seconds
            assertSame(manager.getAuthorizedServices(), lastGood);
            manager.nowMillis += 4999;
            assertEquals(manager.reloadIfModified(), RETRY_PENDING);
            manager.nowMillis++;
            assertEquals(manager.reloadIfModified(), FAILED);
            assertSame(manager.getAuthorizedServices(), lastGood);

            write(path, SECOND_SERVICES, modifiedMillis += 2000);
            assertEquals(manager.reloadIfModified(), RELOADED);
            lastGood = manager.getAuthorizedServices();
            assertTrue(lastGood.contains("example.second"));

            write(path, "{invalid", modifiedMillis + 2000);
            assertEquals(manager.reloadIfModified(), FAILED); // backoff starts again at 2 seconds
            assertSame(manager.getAuthorizedServices(), lastGood);
            manager.nowMillis += 1999;
            assertEquals(manager.reloadIfModified(), RETRY_PENDING);
            manager.nowMillis++;
            assertEquals(manager.reloadIfModified(), FAILED);
            assertSame(manager.getAuthorizedServices(), lastGood);
        } finally {
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS, originalMaxBackoff);
            Files.deleteIfExists(path);
        }
    }

    @Test
    public void testBackgroundTaskReschedulesAfterFailure() throws Exception {
        Path path = Files.createTempFile("authorized-services-background-failure", ".json");
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        String originalFrequency = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS);
        String originalMaxBackoff = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS);
        long modifiedMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(2);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, path.toString());
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS, "3");
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS, "5");
            write(path, FIRST_SERVICES, modifiedMillis);
            ManualTimeManager manager = new ManualTimeManager();
            manager.loadAuthorizedServices();
            AuthorizedServices lastGood = manager.getAuthorizedServices();

            write(path, "{invalid", modifiedMillis += 2000);
            manager.runReloadTask(); // first failure: retry after 3 seconds
            assertEquals(manager.scheduledDelays, List.of(3L));
            assertSame(manager.getAuthorizedServices(), lastGood);

            manager.nowMillis += 3000;
            manager.runReloadTask(); // retry fails: retry after 5 seconds
            assertEquals(manager.scheduledDelays, List.of(3L, 3L));
            assertSame(manager.getAuthorizedServices(), lastGood);

            manager.nowMillis += 3000;
            manager.runReloadTask(); // 2 seconds remain before retry
            assertEquals(manager.scheduledDelays, List.of(3L, 3L, 2L));
            assertSame(manager.getAuthorizedServices(), lastGood);

            manager.nowMillis += 2000;
            manager.runReloadTask(); // retry still runs after the pending check
            assertEquals(manager.scheduledDelays, List.of(3L, 3L, 2L, 3L));
            assertSame(manager.getAuthorizedServices(), lastGood);

            write(path, SECOND_SERVICES, modifiedMillis + 2000);
            manager.nowMillis += 3000;
            manager.runReloadTask();
            assertEquals(manager.scheduledDelays, List.of(3L, 3L, 2L, 3L, 3L));
            assertTrue(manager.getAuthorizedServices().contains("example.second"));
        } finally {
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS, originalMaxBackoff);
            Files.deleteIfExists(path);
        }
    }

    @Test
    public void testBackgroundTaskPublishesUpdates() throws Exception {
        Path path = Files.createTempFile("authorized-services-background", ".json");
        String originalPath = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME);
        String originalFrequency = System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS);
        AuthorizedServicesManager manager = manager(true);
        long modifiedMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(2);
        try {
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, path.toString());
            System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS, "1");
            write(path, FIRST_SERVICES, modifiedMillis);
            manager.loadAuthorizedServices();
            manager.initializeReloadScheduler();

            write(path, SECOND_SERVICES, modifiedMillis + 2000);
            long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(5);
            while (!manager.getAuthorizedServices().contains("example.second")
                    && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertTrue(manager.getAuthorizedServices().contains("example.second"));
            assertFalse(manager.getAuthorizedServices().contains("example.first"));
        } finally {
            manager.shutdownReloadScheduler();
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME, originalPath);
            restoreProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS, originalFrequency);
            Files.deleteIfExists(path);
        }
    }
}

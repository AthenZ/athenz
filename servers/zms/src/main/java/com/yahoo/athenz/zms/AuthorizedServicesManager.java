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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.zms.config.AllowedOperation;
import com.yahoo.athenz.zms.config.AuthorizedService;
import com.yahoo.athenz.zms.config.AuthorizedServices;
import com.yahoo.rdl.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

class AuthorizedServicesManager {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizedServicesManager.class);

    enum ReloadStatus {
        DISABLED, NOT_MODIFIED, RELOADED, RETRY_PENDING, FAILED
    }

    private static class Snapshot {
        final AuthorizedServices services;
        final Path path;
        final long modifiedMillis;

        Snapshot(AuthorizedServices services, Path path, long modifiedMillis) {
            this.services = services;
            this.path = path;
            this.modifiedMillis = modifiedMillis;
        }
    }

    private final ObjectMapper jsonMapper;
    private final boolean dynamicReload;
    private final Supplier<String> rootDirSupplier;
    private volatile Snapshot snapshot = new Snapshot(emptyServices(), null, -1L);
    private ScheduledExecutorService reloadExecutor;
    private Path failedPath;
    private long failedModifiedMillis = -1L;
    private long retryAfterMillis = -1L;
    private long nextBackoffSeconds = -1L;

    AuthorizedServicesManager(ObjectMapper jsonMapper, boolean dynamicReload, Supplier<String> rootDirSupplier) {
        this.jsonMapper = Objects.requireNonNull(jsonMapper);
        this.dynamicReload = dynamicReload;
        this.rootDirSupplier = Objects.requireNonNull(rootDirSupplier);
    }

    AuthorizedServices getAuthorizedServices() {
        return snapshot.services;
    }

    synchronized void loadAuthorizedServices() {
        Path path = Paths.get(System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                rootDirSupplier.get() + "/conf/zms_server/authorized_services.json"));
        try {
            long modifiedMillis = dynamicReload ? modifiedMillis(path) : -1L;
            AuthorizedServices services = dynamicReload ? readValidated(path) : readCompatible(path);
            if (dynamicReload && modifiedMillis(path) != modifiedMillis) {
                throw new IOException("Authorized services file changed while it was being read");
            }
            snapshot = new Snapshot(services, path, modifiedMillis);
        } catch (Exception ex) {
            LOG.error("Unable to load authorized services file {}: {}", path, ex.getMessage());
            LOG.error("Generating empty authorized service list...");
            snapshot = new Snapshot(emptyServices(), path, -1L);
        }
        clearFailure();
    }

    private static AuthorizedServices emptyServices() {
        AuthorizedServices services = new AuthorizedServices();
        services.setTemplates(new HashMap<>());
        return services;
    }

    private long modifiedMillis(Path path) throws IOException {
        return Files.getLastModifiedTime(path).toMillis();
    }

    private AuthorizedServices readCompatible(Path path) throws IOException {
        AuthorizedServices services = JSON.fromBytes(Files.readAllBytes(path), AuthorizedServices.class);
        return services == null || services.getServices() == null ? emptyServices() : services;
    }

    private AuthorizedServices readValidated(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        JsonNode root = jsonMapper.readTree(data);
        if (root == null || !root.isObject() || !root.has("services") || !root.get("services").isObject()) {
            throw new IllegalArgumentException("Invalid authorized services document in file " + path);
        }

        AuthorizedServices services = JSON.fromBytes(data, AuthorizedServices.class);
        if (services == null || services.getServices() == null) {
            throw new IllegalArgumentException("Invalid authorized services content in file " + path);
        }
        validate(services);
        return services;
    }

    private void validate(AuthorizedServices services) {
        for (Map.Entry<String, AuthorizedService> entry : services.getServices().entrySet()) {
            if (entry.getKey() == null || entry.getKey().isEmpty() || entry.getValue() == null) {
                throw new IllegalArgumentException("Invalid authorized service definition");
            }
            if (entry.getValue().getAllowedOperations() == null) {
                continue;
            }
            for (AllowedOperation operation : entry.getValue().getAllowedOperations()) {
                if (operation == null || operation.getName() == null || operation.getName().isEmpty()) {
                    throw new IllegalArgumentException("Invalid operation for authorized service " + entry.getKey());
                }
                if (operation.getItems() == null) {
                    continue;
                }
                for (Map.Entry<String, Set<String>> item : operation.getItems().entrySet()) {
                    if (item.getKey() == null || item.getKey().isEmpty() || item.getValue() == null
                            || item.getValue().contains(null) || item.getValue().contains("")) {
                        throw new IllegalArgumentException("Invalid operation items for authorized service "
                                + entry.getKey());
                    }
                }
            }
        }
    }

    void initializeReloadScheduler() {
        if (!dynamicReload) {
            return;
        }
        reloadExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "zms-authorized-services-reload");
            thread.setDaemon(true);
            return thread;
        });
        scheduleReload(0);
    }

    void shutdownReloadScheduler() {
        if (reloadExecutor != null) {
            reloadExecutor.shutdownNow();
        }
    }

    private void scheduleReload(long delaySeconds) {
        ScheduledExecutorService executor = reloadExecutor;
        if (executor == null || executor.isShutdown()) {
            return;
        }
        try {
            executor.schedule(this::runReloadTask, delaySeconds, TimeUnit.SECONDS);
        } catch (RejectedExecutionException ex) {
            if (!executor.isShutdown()) {
                LOG.error("Unable to schedule authorized services reload: {}", ex.getMessage());
            }
        }
    }

    private void runReloadTask() {
        long delaySeconds = reloadFrequencySeconds();
        try {
            ReloadStatus status = reloadIfModified();
            if (status == ReloadStatus.FAILED || status == ReloadStatus.RETRY_PENDING) {
                delaySeconds = Math.min(delaySeconds, retryDelaySeconds());
            }
        } catch (Exception ex) {
            LOG.error("Unexpected failure while reloading authorized services: {}", ex.getMessage());
        }
        scheduleReload(delaySeconds);
    }

    synchronized ReloadStatus reloadIfModified() {
        if (!dynamicReload) {
            return ReloadStatus.DISABLED;
        }

        Snapshot current = snapshot;
        Path path = current.path;
        if (path == null) {
            path = Paths.get(System.getProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                    rootDirSupplier.get() + "/conf/zms_server/authorized_services.json"));
        }

        long modifiedMillis;
        try {
            modifiedMillis = modifiedMillis(path);
        } catch (IOException ex) {
            if (retryPending(path, -1L)) {
                return ReloadStatus.RETRY_PENDING;
            }
            recordFailure(path, -1L);
            LOG.error("Unable to check authorized services file {} for changes: {}", path, ex.getMessage());
            return ReloadStatus.FAILED;
        }

        if (modifiedMillis == current.modifiedMillis) {
            clearFailure();
            return ReloadStatus.NOT_MODIFIED;
        }
        if (retryPending(path, modifiedMillis)) {
            return ReloadStatus.RETRY_PENDING;
        }

        try {
            AuthorizedServices services = readValidated(path);
            if (modifiedMillis(path) != modifiedMillis) {
                throw new IOException("Authorized services file changed while it was being read");
            }
            snapshot = new Snapshot(services, path, modifiedMillis);
            clearFailure();
            LOG.info("Reloaded authorized services file {}", path);
            return ReloadStatus.RELOADED;
        } catch (Exception ex) {
            recordFailure(path, modifiedMillis);
            LOG.error("Unable to reload authorized services file {}. Keeping the previous services: {}",
                    path, ex.getMessage());
            return ReloadStatus.FAILED;
        }
    }

    private long reloadFrequencySeconds() {
        return positiveLongProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS,
                ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_FREQUENCY_SECONDS_DEFAULT);
    }

    private long maxBackoffSeconds() {
        return Math.max(reloadFrequencySeconds(), positiveLongProperty(
                ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS,
                ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_RELOAD_MAX_BACKOFF_SECONDS_DEFAULT));
    }

    private long positiveLongProperty(String name, String defaultValue) {
        try {
            long value = Long.parseLong(System.getProperty(name, defaultValue));
            if (value > 0) {
                return value;
            }
        } catch (NumberFormatException ex) {
            LOG.error("Invalid authorized services reload property {}: {}", name, ex.getMessage());
        }
        return Long.parseLong(defaultValue);
    }

    private boolean retryPending(Path path, long modifiedMillis) {
        return Objects.equals(path, failedPath) && modifiedMillis == failedModifiedMillis
                && System.currentTimeMillis() < retryAfterMillis;
    }

    private long retryDelaySeconds() {
        long remainingMillis = retryAfterMillis - System.currentTimeMillis();
        return remainingMillis <= 0 ? 0 : Math.max(1, TimeUnit.MILLISECONDS.toSeconds(remainingMillis));
    }

    private void recordFailure(Path path, long modifiedMillis) {
        long backoffSeconds = nextBackoffSeconds <= 0 ? reloadFrequencySeconds() : nextBackoffSeconds;
        backoffSeconds = Math.min(backoffSeconds, maxBackoffSeconds());
        failedPath = path;
        failedModifiedMillis = modifiedMillis;
        retryAfterMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(backoffSeconds);
        nextBackoffSeconds = backoffSeconds > maxBackoffSeconds() / 2 ? maxBackoffSeconds() : backoffSeconds * 2;
    }

    private void clearFailure() {
        failedPath = null;
        failedModifiedMillis = -1L;
        retryAfterMillis = -1L;
        nextBackoffSeconds = -1L;
    }
}

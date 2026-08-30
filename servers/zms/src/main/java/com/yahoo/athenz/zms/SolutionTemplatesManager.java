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
import com.yahoo.athenz.zms.config.SolutionTemplates;
import com.yahoo.rdl.JSON;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

class SolutionTemplatesManager {

    private static final Logger LOG = LoggerFactory.getLogger(SolutionTemplatesManager.class);

    private final ObjectMapper jsonMapper;
    private final boolean dynamicReload;
    private final Supplier<String> rootDirSupplier;
    private final Consumer<SolutionTemplatesSnapshot> snapshotConsumer;
    private final AtomicReference<SolutionTemplatesSnapshot> solutionTemplatesSnapshot = new AtomicReference<>();
    private ScheduledExecutorService solutionTemplatesReloadExecutor = null;
    private volatile Path solutionTemplatesReloadFailedPath = null;
    private volatile long solutionTemplatesReloadFailedModifiedMillis = -1L;
    private volatile long solutionTemplatesReloadFailedRetryMillis = -1L;
    private volatile long solutionTemplatesReloadFailureBackoffSeconds = -1L;

    SolutionTemplatesManager(final ObjectMapper jsonMapper, final boolean dynamicReload,
            final Supplier<String> rootDirSupplier,
            final Consumer<SolutionTemplatesSnapshot> snapshotConsumer) {

        this.jsonMapper = Objects.requireNonNull(jsonMapper);
        this.dynamicReload = dynamicReload;
        this.rootDirSupplier = Objects.requireNonNull(rootDirSupplier);
        this.snapshotConsumer = Objects.requireNonNull(snapshotConsumer);
    }

    void loadSolutionTemplates() {

        String solutionTemplatesFname = solutionTemplatesFileName();
        Path path = Paths.get(solutionTemplatesFname);
        try {
            long modifiedMillis = solutionTemplatesModifiedMillis(path);
            SolutionTemplates solutionTemplates = dynamicReload
                    ? readSolutionTemplates(path)
                    : readSolutionTemplatesCompatible(path);
            setServerSolutionTemplates(solutionTemplates, path, modifiedMillis);
        } catch (IOException ex) {

            // We have failed to read our solution templates file (e.g. missing
            // or transient io failure), so generate an empty template list
            // without recording any modified timestamp so the dynamic reload
            // task will retry loading the file once it becomes available.

            LOG.error("Unable to load solution templates file {}: {}", solutionTemplatesFname, ex.getMessage());
            LOG.error("Generating empty solution template list...");
            setServerSolutionTemplates(emptySolutionTemplates(), path, -1L);
        }
    }

    String solutionTemplatesFileName() {
        return System.getProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                rootDirSupplier.get() + "/conf/zms_server/solution_templates.json");
    }

    long solutionTemplatesModifiedMillis(Path path) throws IOException {
        return Files.getLastModifiedTime(path).toMillis();
    }

    void initializeReloadScheduler() {
        if (!dynamicReload) {
            return;
        }

        solutionTemplatesReloadExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName("zms-solution-templates-reload");
            thread.setDaemon(true);
            return thread;
        });
        scheduleSolutionTemplatesReload(0);
    }

    void shutdownReloadScheduler() {
        ScheduledExecutorService executor = solutionTemplatesReloadExecutor;
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    void scheduleSolutionTemplatesReload(long delaySeconds) {
        ScheduledExecutorService executor = solutionTemplatesReloadExecutor;
        if (executor == null || executor.isShutdown()) {
            return;
        }
        try {
            executor.schedule(this::runSolutionTemplatesReloadTask, delaySeconds, TimeUnit.SECONDS);
        } catch (RejectedExecutionException ex) {
            if (!executor.isShutdown()) {
                LOG.error("Unable to schedule the solution templates reload task: {}", ex.getMessage());
            }
        }
    }

    void runSolutionTemplatesReloadTask() {
        long delaySeconds = solutionTemplatesReloadFrequencySeconds();
        try {
            SolutionTemplatesReloadStatus reloadStatus = reloadSolutionTemplatesIfModified();
            delaySeconds = solutionTemplatesReloadDelaySeconds(reloadStatus);
        } catch (Exception ex) {
            LOG.error("Unexpected failure while running the solution templates reload task: {}", ex.getMessage());
        }
        scheduleSolutionTemplatesReload(delaySeconds);
    }

    long solutionTemplatesReloadDelaySeconds(SolutionTemplatesReloadStatus reloadStatus) {
        if (reloadStatus == SolutionTemplatesReloadStatus.FAILED
                || reloadStatus == SolutionTemplatesReloadStatus.RETRY_PENDING) {
            return Math.min(solutionTemplatesReloadFrequencySeconds(), solutionTemplatesReloadRetryDelaySeconds());
        }
        return solutionTemplatesReloadFrequencySeconds();
    }

    long solutionTemplatesReloadRetryDelaySeconds() {
        long retryMillis = solutionTemplatesReloadFailedRetryMillis;
        if (retryMillis <= 0) {
            return solutionTemplatesReloadFrequencySeconds();
        }

        long remainingMillis = retryMillis - currentTimeMillis();
        if (remainingMillis <= 0) {
            return 0;
        }
        return Math.max(1, TimeUnit.MILLISECONDS.toSeconds(remainingMillis));
    }

    long solutionTemplatesReloadFrequencySeconds() {
        return positiveLongSystemProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS,
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_FREQUENCY_SECONDS_DEFAULT);
    }

    long solutionTemplatesReloadMaxBackoffSeconds() {
        return Math.max(solutionTemplatesReloadFrequencySeconds(), positiveLongSystemProperty(
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS,
                ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_RELOAD_MAX_BACKOFF_SECONDS_DEFAULT));
    }

    long positiveLongSystemProperty(String propertyName, String defaultValue) {
        long value = Long.parseLong(System.getProperty(propertyName, defaultValue));
        return value > 0 ? value : Long.parseLong(defaultValue);
    }

    boolean solutionTemplatesReloadRetryPending(Path path, long modifiedMillis) {
        return Objects.equals(path, solutionTemplatesReloadFailedPath)
                && modifiedMillis == solutionTemplatesReloadFailedModifiedMillis
                && currentTimeMillis() < solutionTemplatesReloadFailedRetryMillis;
    }

    void recordSolutionTemplatesReloadFailure(Path path, long modifiedMillis) {
        final long backoffSeconds = solutionTemplatesReloadNextBackoffSeconds();
        solutionTemplatesReloadFailedPath = path;
        solutionTemplatesReloadFailedModifiedMillis = modifiedMillis;
        solutionTemplatesReloadFailedRetryMillis = currentTimeMillis() + TimeUnit.SECONDS.toMillis(backoffSeconds);
        solutionTemplatesReloadFailureBackoffSeconds = solutionTemplatesReloadNextBackoffSeconds(backoffSeconds);
    }

    long solutionTemplatesReloadNextBackoffSeconds() {
        long backoffSeconds = solutionTemplatesReloadFailureBackoffSeconds;
        if (backoffSeconds <= 0) {
            backoffSeconds = solutionTemplatesReloadFrequencySeconds();
        }
        return Math.min(backoffSeconds, solutionTemplatesReloadMaxBackoffSeconds());
    }

    long solutionTemplatesReloadNextBackoffSeconds(long currentBackoffSeconds) {
        final long maxBackoffSeconds = solutionTemplatesReloadMaxBackoffSeconds();
        if (currentBackoffSeconds >= maxBackoffSeconds || currentBackoffSeconds > maxBackoffSeconds / 2) {
            return maxBackoffSeconds;
        }
        return currentBackoffSeconds * 2;
    }

    void clearSolutionTemplatesReloadFailure() {
        solutionTemplatesReloadFailedPath = null;
        solutionTemplatesReloadFailedModifiedMillis = -1L;
        solutionTemplatesReloadFailedRetryMillis = -1L;
        solutionTemplatesReloadFailureBackoffSeconds = -1L;
    }

    long currentTimeMillis() {
        return System.currentTimeMillis();
    }

    SolutionTemplates readSolutionTemplatesCompatible(Path path) throws IOException {
        SolutionTemplates solutionTemplates = JSON.fromBytes(Files.readAllBytes(path), SolutionTemplates.class);
        if (solutionTemplates == null || solutionTemplates.getTemplates() == null) {
            return emptySolutionTemplates();
        }
        validateSolutionTemplatesConfig(solutionTemplates, false);
        return solutionTemplates;
    }

    SolutionTemplates readSolutionTemplates(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);

        // Parse the document first to verify that it contains a valid json
        // object before converting it to a SolutionTemplates object. this is
        // required since JSON.fromBytes returns null both for empty documents
        // and when the document is corrupted, and we must not treat a
        // corrupted document as an empty template list.

        JsonNode rootNode;
        try {
            rootNode = jsonMapper.readTree(data);
        } catch (Exception ex) {
            throw new RuntimeException("Unable to parse solution templates document in file "
                    + path + ": " + ex.getMessage(), ex);
        }
        if (rootNode == null || !rootNode.isObject()) {
            throw new RuntimeException("Invalid solution templates document in file " + path);
        }
        SolutionTemplates solutionTemplates = JSON.fromBytes(data, SolutionTemplates.class);
        if (solutionTemplates == null) {
            throw new RuntimeException("Invalid solution templates content in file " + path);
        }
        if (solutionTemplates.getTemplates() == null) {
            solutionTemplates.setTemplates(new HashMap<>());
        }
        validateSolutionTemplatesConfig(solutionTemplates, true);
        return solutionTemplates;
    }

    SolutionTemplates emptySolutionTemplates() {
        SolutionTemplates solutionTemplates = new SolutionTemplates();
        solutionTemplates.setTemplates(new HashMap<>());
        return solutionTemplates;
    }

    void validateSolutionTemplatesConfig(SolutionTemplates solutionTemplates) {
        validateSolutionTemplatesConfig(solutionTemplates, true);
    }

    void validateSolutionTemplatesConfig(SolutionTemplates solutionTemplates, boolean strictPublishedSnapshot) {

        // Validate that we don't have any null entries or roles with both
        // members and trust attributes.

        for (Map.Entry<String, Template> entry : solutionTemplates.getTemplates().entrySet()) {
            final String templateName = entry.getKey();
            final Template template = entry.getValue();
            if (template == null) {
                LOG.error("Solution Template {} has a null definition", templateName);
                throw new RuntimeException("Solution Template " + templateName + " has a null definition");
            }
            if (strictPublishedSnapshot) {
                validateSolutionTemplatePublishedSnapshot(templateName, template);
            }
            if (template.getRoles() == null) {
                continue;
            }
            for (Role role : template.getRoles()) {
                if (role == null) {
                    LOG.error("Solution Template {} contains a null role", templateName);
                    throw new RuntimeException("Solution Template " + templateName + " contains a null role");
                }
                if (!StringUtil.isEmpty(role.getTrust()) && role.getRoleMembers() != null
                        && !role.getRoleMembers().isEmpty()) {
                    LOG.error("Solution Template {} role {} has both trust and members defined",
                            templateName, role.getName());
                    throw new RuntimeException("Solution Template " + templateName + " role " + role.getName()
                            + " has both trust and members defined");
                }
            }
        }
    }

    void validateSolutionTemplatePublishedSnapshot(String templateName, Template template) {
        if (template.getMetadata() == null) {
            LOG.error("Solution Template {} has null metadata", templateName);
            throw new RuntimeException("Solution Template " + templateName + " has null metadata");
        }
        validateNoNullEntries(templateName, "role", template.getRoles());
        validateNoNullEntries(templateName, "policy", template.getPolicies());
        validateNoNullEntries(templateName, "group", template.getGroups());
        validateNoNullEntries(templateName, "service", template.getServices());
        if (template.getRoles() != null) {
            for (Role role : template.getRoles()) {
                validateNoNullEntries(templateName, "role member", role.getRoleMembers());
            }
        }
        if (template.getPolicies() != null) {
            for (Policy policy : template.getPolicies()) {
                validateNoNullEntries(templateName, "policy assertion", policy.getAssertions());
            }
        }
        if (template.getGroups() != null) {
            for (Group group : template.getGroups()) {
                validateNoNullEntries(templateName, "group member", group.getGroupMembers());
            }
        }
        if (template.getServices() != null) {
            for (ServiceIdentity service : template.getServices()) {
                validateNoNullEntries(templateName, "service public key", service.getPublicKeys());
            }
        }
    }

    void validateNoNullEntries(String templateName, String entryType, Collection<?> entries) {
        if (entries == null) {
            return;
        }
        for (Object entry : entries) {
            if (entry == null) {
                LOG.error("Solution Template {} contains a null {}", templateName, entryType);
                throw new RuntimeException("Solution Template " + templateName + " contains a null " + entryType);
            }
        }
    }

    void validateSolutionTemplateReloadVersions(SolutionTemplates currentTemplates,
            SolutionTemplates updatedTemplates) {

        if (solutionTemplatesEmpty(currentTemplates) || solutionTemplatesEmpty(updatedTemplates)) {
            return;
        }

        for (Map.Entry<String, Template> entry : updatedTemplates.getTemplates().entrySet()) {
            final String templateName = entry.getKey();
            final Template currentTemplate = currentTemplates.getTemplates().get(templateName);
            final Template updatedTemplate = entry.getValue();
            validateSolutionTemplateReloadVersion(templateName, currentTemplate, updatedTemplate);
        }
    }

    boolean solutionTemplatesEmpty(SolutionTemplates solutionTemplates) {
        return solutionTemplates == null || solutionTemplates.getTemplates() == null
                || solutionTemplates.getTemplates().isEmpty();
    }

    void validateSolutionTemplateReloadVersion(String templateName, Template currentTemplate, Template updatedTemplate) {
        if (currentTemplate == null || Objects.equals(currentTemplate, updatedTemplate)) {
            return;
        }

        final Integer currentLatestVersion = solutionTemplateLatestVersion(currentTemplate);
        final Integer updatedLatestVersion = solutionTemplateLatestVersion(updatedTemplate);
        if (solutionTemplateLatestVersionIncremented(currentLatestVersion, updatedLatestVersion)) {
            return;
        }

        LOG.error("Solution Template {} changed without incrementing latestVersion from {} to {}",
                templateName, currentLatestVersion, updatedLatestVersion);
        throw new RuntimeException("Solution Template " + templateName
                + " changed without incrementing latestVersion from " + currentLatestVersion
                + " to " + updatedLatestVersion);
    }

    boolean solutionTemplateLatestVersionIncremented(Integer currentLatestVersion, Integer updatedLatestVersion) {
        return currentLatestVersion != null && updatedLatestVersion != null
                && updatedLatestVersion > currentLatestVersion;
    }

    Integer solutionTemplateLatestVersion(Template template) {
        return template == null || template.getMetadata() == null ? null : template.getMetadata().getLatestVersion();
    }

    SolutionTemplatesSnapshot newSolutionTemplatesSnapshot(SolutionTemplates solutionTemplates, Path path,
            long modifiedMillis) {
        List<String> templateNames = new ArrayList<>(solutionTemplates.names());
        Collections.sort(templateNames);
        return new SolutionTemplatesSnapshot(solutionTemplates, Collections.unmodifiableList(templateNames), path,
                modifiedMillis);
    }

    void setServerSolutionTemplates(SolutionTemplates solutionTemplates, Path path, long modifiedMillis) {
        publishSolutionTemplatesSnapshot(newSolutionTemplatesSnapshot(solutionTemplates, path, modifiedMillis), true);
    }

    void publishSolutionTemplatesSnapshot(SolutionTemplatesSnapshot newSnapshot, boolean force) {
        while (true) {
            SolutionTemplatesSnapshot currentSnapshot = solutionTemplatesSnapshot.get();
            if (!force && currentSnapshot != null && Objects.equals(currentSnapshot.path, newSnapshot.path)
                    && currentSnapshot.modifiedMillis == newSnapshot.modifiedMillis) {
                return;
            }
            if (solutionTemplatesSnapshot.compareAndSet(currentSnapshot, newSnapshot)) {
                clearSolutionTemplatesReloadFailure();
                snapshotConsumer.accept(newSnapshot);
                return;
            }
        }
    }

    SolutionTemplatesSnapshot getSolutionTemplatesSnapshot() {
        SolutionTemplatesSnapshot snapshot = solutionTemplatesSnapshot.get();
        if (snapshot != null) {
            return snapshot;
        }

        SolutionTemplatesSnapshot emptySnapshot = newSolutionTemplatesSnapshot(emptySolutionTemplates(), null, -1L);
        if (solutionTemplatesSnapshot.compareAndSet(null, emptySnapshot)) {
            clearSolutionTemplatesReloadFailure();
            snapshotConsumer.accept(emptySnapshot);
            return emptySnapshot;
        }
        return solutionTemplatesSnapshot.get();
    }

    SolutionTemplatesReloadStatus reloadSolutionTemplatesIfModified() {
        if (!dynamicReload) {
            return SolutionTemplatesReloadStatus.DISABLED;
        }

        SolutionTemplatesSnapshot currentSnapshot = getSolutionTemplatesSnapshot();
        Path path = currentSnapshot.path;
        if (path == null) {
            path = Paths.get(solutionTemplatesFileName());
        }

        long modifiedMillis;
        try {
            modifiedMillis = solutionTemplatesModifiedMillis(path);
        } catch (IOException ex) {
            if (solutionTemplatesReloadRetryPending(path, -1L)) {
                return SolutionTemplatesReloadStatus.RETRY_PENDING;
            }
            LOG.error("Unable to check solution templates file {} for changes: {}",
                    path, ex.getMessage());
            recordSolutionTemplatesReloadFailure(path, -1L);
            return SolutionTemplatesReloadStatus.FAILED;
        }

        if (modifiedMillis == currentSnapshot.modifiedMillis) {
            clearSolutionTemplatesReloadFailure();
            return SolutionTemplatesReloadStatus.NOT_MODIFIED;
        }
        if (solutionTemplatesReloadRetryPending(path, modifiedMillis)) {
            return SolutionTemplatesReloadStatus.RETRY_PENDING;
        }

        try {
            SolutionTemplates solutionTemplates = readSolutionTemplates(path);
            if (solutionTemplatesPostReadCheckFailed(path, modifiedMillis)) {
                return SolutionTemplatesReloadStatus.FAILED;
            }
            validateSolutionTemplateReloadVersions(currentSnapshot.templates, solutionTemplates);
            SolutionTemplatesSnapshot newSnapshot = newSolutionTemplatesSnapshot(solutionTemplates, path,
                    modifiedMillis);
            publishSolutionTemplatesSnapshot(newSnapshot, false);
            LOG.info("Reloaded solution templates file {}", path);
            return SolutionTemplatesReloadStatus.RELOADED;
        } catch (IOException ex) {
            LOG.error("Unable to read solution templates file {}. Keeping the previous templates: {}",
                    path, ex.getMessage());
            recordSolutionTemplatesReloadFailure(path, modifiedMillis);
            return SolutionTemplatesReloadStatus.FAILED;
        } catch (Exception ex) {
            recordSolutionTemplatesReloadFailure(path, modifiedMillis);
            LOG.error("Unable to reload solution templates file {}. Keeping the previous templates: {}",
                    path, ex.getMessage());
            return SolutionTemplatesReloadStatus.FAILED;
        }
    }

    boolean solutionTemplatesPostReadCheckFailed(Path path, long modifiedMillis) {
        final long postReadModifiedMillis;
        try {
            postReadModifiedMillis = solutionTemplatesModifiedMillis(path);
        } catch (IOException ex) {
            LOG.error("Unable to check solution templates file {} after reading it. "
                    + "Keeping the previous templates: {}", path, ex.getMessage());
            recordSolutionTemplatesReloadFailure(path, modifiedMillis);
            return true;
        }
        if (postReadModifiedMillis == modifiedMillis) {
            return false;
        }
        LOG.error("Solution templates file {} changed while it was being read. "
                + "Keeping the previous templates and retrying later", path);
        recordSolutionTemplatesReloadFailure(path, modifiedMillis);
        return true;
    }

    AtomicReference<SolutionTemplatesSnapshot> solutionTemplatesSnapshotReference() {
        return solutionTemplatesSnapshot;
    }

    ScheduledExecutorService solutionTemplatesReloadExecutor() {
        return solutionTemplatesReloadExecutor;
    }

    void setSolutionTemplatesReloadExecutor(final ScheduledExecutorService executor) {
        solutionTemplatesReloadExecutor = executor;
    }
}

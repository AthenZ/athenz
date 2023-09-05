/*
 * Copyright The Athenz Authors.
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
package com.yahoo.athenz.common.server.util.config;

import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigDuration;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProvider;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProviderAwsParametersStore;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProviderFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.Closeable;
import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Maintain a set of {@link ConfigProvider.ConfigSource}s (for example - a config file),
 *  and (optionally) periodically reload them into the system-properties - possibly calling change-callbacks. <br>
 * These configs can then be accessed via {@link System#getProperty}, or directly from the ConfigManager -
 *  either via {@link #getConfigValue} or {@link #getAllConfigValues()}.
 * <p>
 * <h3>Simple usage example:</h3>
 * <pre>{@code
 *      new ConfigManager()
 *              .addConfigSource("aws-param-store:///demo")
 *              .addConfigSource("prop-file:///opt/demo/conf/demo.conf");
 *      String confValue = System.getProperty("demo.size");
 *  }</pre>
 *
 * <h3>Auto-reload example:</h3>
 * Reloading every 300 seconds by default (controlled by the configuration "reload-configs-seconds"): <pre>{@code
 *      new ConfigManager("reload-configs-seconds", 300, TimeUnit.SECONDS) ...
 *  }</pre>
 *
 * <h3>Config-Providers</h3>
 * Config-sources are added by a string name
 * "by name"If so configured, whenever config-sources are reloaded, and one or more config-values change -
 *  then the system-properties are updated (including a deletion of a property),
 *  and change-callbacks are called (see {@link #registerChangeCallback}). <br>
 * <br>
 *
 * <h3>Dynamic Reload</h3>
 * If so configured, whenever config-sources are reloaded, and one or more config-values change -
 *  then the system-properties are updated (including a deletion of a property),
 *  and change-callbacks are called (see {@link #registerChangeCallback}). <br>
 * <br>
 * Be aware of the DynamicConfig... classes (see base-class {@link com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfig})
 *  that works in tandem with {@link ConfigManager} to provide dynamically changing and efficient configurations
 *  (especially - be aware of the slick {@link DynamicConfigDuration}). <br>
 * <br>
 * <h3>Note about system-properties</h3>
 * By default - this class reflects all configs onto system-properties
 *  (using {@link #systemSetProperty} and {@link #systemClearProperty}).
 * Also, {@link #getConfigValue} uses the system-properties as fallback in case a property is
 *  not set in the config-sources (using {@link #systemGetProperty}). <br>
 * This behaviour can be disabled/changed by overriding these "system..." methods. <br>
 * <br>
 * <h3>Config-Values Translation</h3>
 * All config values (originated from a config-source or from {@link #systemGetProperty})
 *  are "translated" using {@link #translateConfigValue} (which by default does nothing). <br>
 * <br>
 */
public class ConfigManager implements Closeable {

    /** See {@link #addProvider}. All access must be "synchronized" ! */
    private final List<ConfigProvider> configProviders = new LinkedList<>();

    /** See {@link #addConfigSource}. All access must be "synchronized" ! */
    private final List<ConfigProvider.ConfigSource> configSources = new LinkedList<>();

    /** See {@link #registerChangeCallback}. All access must be "synchronized" ! */
    private final Set<Runnable> changeCallbacks = new HashSet<>();

    /** The current config-entries */
    private final Map<String, ConfigEntry> previousConfigs = new ConcurrentHashMap<>();

    private final Thread reloadSourcesThread;
    private boolean isClosed = false;

    /**
     * Whenever we reload a config-source - this is incremented.
     * At all times, we know - per config-entry - at what generation it was last encountered.
     */
    private long lastReloadGeneration = 0;

    /** Never sleep less than 1 second - a safety mechanism to avoid 100% CPU loop */
    private static final long MINIMAL_PERIODIC_RELOAD_INTERVAL = 1000L;

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());


    /** Construct a NON-RELOADING config-manager */
    public ConfigManager() {
        // Add all standard providers.
        init();

        reloadSourcesThread = null;
    }

    /**
     * Construct a RELOADING config-manager.
     * The periodic reload interval is also configurable.
     * Note that
     */
    public ConfigManager(String reloadConfigKey, long reloadDefaultValue, TimeUnit reloadTimeUnit) {
        // Add all standard providers.
        init();

        // Start a thread to periodically reload configs.
        reloadSourcesThread = periodicallyReloadConfigs(reloadConfigKey, reloadDefaultValue, reloadTimeUnit);
    }

    /** Overridable: This is called upon construction and add all standard providers */
    protected void init() {
        addProvider(new ConfigProviderFile());
        addProvider(new ConfigProviderAwsParametersStore());
    }

    /**
     * Add a config-provider, so that when {@link #addConfigSource(String)} is called,
     *  this provider can inspect the source-description and provide a matching source.
     */
    public synchronized ConfigManager addProvider(ConfigProvider provider) {
        configProviders.add(provider);
        return this;
    }

    /** Undo a call to {@link #addProvider} */
    public synchronized boolean removeProvider(ConfigProvider provider) {
        return configProviders.remove(provider);
    }

    /** Get all config-providers */
    public synchronized ConfigProvider[] getConfigProviders() {
        return configProviders.toArray(new ConfigProvider[0]);
    }

    /**
     * Add a config-source. Sources that are added earlier have higher priority
     *  (values from early-added sources prevail over values from later-added sources).
     * A source-description is "inspected" by all registered {@link ConfigProvider}s -
     *  and the first provider to build a {@link ConfigProvider.ConfigSource} "wins".
     * Source-description is trimmed. Empty source-descriptions is ignored.
     */
    public synchronized ConfigManager addConfigSource(String sourceDescription) {

        // Trim the description, and skip if empty.
        String trimmedSourceDescription = sourceDescription.trim();
        if (trimmedSourceDescription.isEmpty()) {
            return this;
        }

        // Skip if this source-description is already added.
        if (configSources.stream().anyMatch(configSource -> configSource.sourceDescription.equals(trimmedSourceDescription))) {
            LOG.warn("Config-source description {} added twice. Ignoring.", Utils.jsonSerializeForLog(trimmedSourceDescription));
            return this;
        }

        // Allow all config-providers to inspect the source-description and provide a config-source.
        ConfigProvider.ConfigSource configSource = null;
        for (ConfigProvider provider : configProviders) {
            try {
                configSource = provider.tryToBuildConfigSource(trimmedSourceDescription);
                if (configSource != null) {
                    break;
                }
            } catch (Exception exception) {
                LOG.warn("Ignoring exception when config-provider {} tried to build config-source for source-description {}: ", provider, Utils.jsonSerializeForLog(trimmedSourceDescription), exception);
            }
        }
        if (configSource == null) {
            LOG.warn("No config-provider could provide a config-source for source-description {}. Ignoring.", Utils.jsonSerializeForLog(trimmedSourceDescription));
            return this;
        }

        addConfigSource(configSource);
        return this;
    }


    /**
     * Add a config-source object - without "consulting" the {@link ConfigProvider}s.
     * Sources that are added earlier have higher priority
     *  (values from early-added sources prevail over values from later-added sources).
     */
    public synchronized ConfigManager addConfigSource(ConfigProvider.ConfigSource configSource) {

        if (configSources.contains(configSource)) {
            LOG.warn("Config-source {} added twice. Ignoring.", configSource);
            return this;
        }

        // Add the config-source.
        LOG.info("Added config-source: {}", configSource);
        Set<ConfigProvider.ConfigSource> higherPrioritySources = new HashSet<>(configSources);
        configSources.add(configSource);
        List<ChangeLog> changeLogs = new LinkedList<>();
        reloadConfigSource(configSource, higherPrioritySources, -1, changeLogs, true);

        // Log and call change-callbacks.
        digestChangeLogs(changeLogs);
        return this;
    }

    /** Undo a call to {@link #addConfigSource(String)} */
    public synchronized boolean removeConfigSource(String sourceDescription) {
        String trimmedSourceDescription = sourceDescription.trim();
        boolean anySourceRemoved = configSources.removeIf(configSource -> configSource.sourceDescription.equals(trimmedSourceDescription));
        if (anySourceRemoved) {
            reloadAllConfigs();
        }
        return anySourceRemoved;
    }

    /** Undo a call to {@link #addConfigSource(ConfigProvider.ConfigSource)} */
    public synchronized boolean removeConfigSource(ConfigProvider.ConfigSource configSource) {
        boolean anySourceRemoved = configSources.remove(configSource);
        if (anySourceRemoved) {
            reloadAllConfigs();
        }
        return anySourceRemoved;
    }

    /** Get all config-sources */
    public synchronized ConfigProvider.ConfigSource[] getConfigSources() {
        return configSources.toArray(new ConfigProvider.ConfigSource[0]);
    }

    /** Whenever configs change in the config-sources - call this callback */
    public synchronized ConfigManager registerChangeCallback(@Nonnull Runnable changeCallback) {
        changeCallbacks.add(changeCallback);
        return this;
    }

    /** Undo a call to {@link #registerChangeCallback} */
    public synchronized void unregisterChangeCallback(@Nonnull Runnable changeCallback) {
        changeCallbacks.remove(changeCallback);
    }

    /** Force reload of all config-sources. */
    public synchronized void reloadAllConfigs() {
        // Query all sources.
        long newestObsoleteGeneration = lastReloadGeneration;
        List<ChangeLog> changeLogs = new LinkedList<>();
        Set<ConfigProvider.ConfigSource> alreadyLoadedSources = new HashSet<>();
        for (ConfigProvider.ConfigSource configSource : configSources) {
            reloadConfigSource(
                    configSource,
                    alreadyLoadedSources,
                    newestObsoleteGeneration,
                    changeLogs,
                    false);
            alreadyLoadedSources.add(configSource);
        }

        // If a config-entry was loaded in a very old generation (before this method-call) - then it should be removed.
        previousConfigs.values().removeIf(configEntry -> {
            if (configEntry.reloadGeneration <= newestObsoleteGeneration) {
                systemClearProperty(configEntry.key);
                changeLogs.add(new ChangeLog(configEntry, null));
                return true;   // remove config-entry
            } else {
                return false;
            }
        });

        // Log and call change-callbacks.
        digestChangeLogs(changeLogs);
    }

    /**
     * Get the current value for a config-key.
     * If there is no value in the config-sources - will fallback to {@link #systemGetProperty(String)}.
     */
    public @Nullable String getConfigValue(String configKey) {
        ConfigEntry configEntry = previousConfigs.get(configKey);
        return translateConfigValue(
                configKey,
                (configEntry == null)
                        ? systemGetProperty(configKey)
                        : configEntry.value);
    }

    /**
     * Get all configs (a cloned map).
     * This will only return values from the config-sources: not values from {@link System#getProperty}.
     */
    public Map<String, String> getAllConfigValues() {
        HashMap<String, String> result = new HashMap<>(previousConfigs.size());
        previousConfigs.forEach((configKey, configEntry) -> result.put(configKey, translateConfigValue(configKey, configEntry.value)));
        return result;
    }

    /** Stop reloading config source and update config-values  */
    @Override
    public void close() {
        isClosed = true;
        while ((reloadSourcesThread != null) && reloadSourcesThread.isAlive()) {
            reloadSourcesThread.interrupt();
            try {
                Thread.sleep(10);
            } catch (InterruptedException ignored) {
            }
        }
    }

    /** Overridable: like {@link System#getProperty(String)} */
    protected String systemGetProperty(String key) {
        return System.getProperty(key);
    }

    /** Overridable: like {@link System#clearProperty(String)} */
    protected void systemClearProperty(String key) {
        System.clearProperty(key);
    }

    /** Overridable: like {@link System#setProperty(String, String)} (property-value is NOT translated by {@link #translateConfigValue}) */
    protected void systemSetProperty(String key, String value) {
        System.setProperty(key, value);
    }

    /**
     * Overridable: whenever getting a config-value (either if it originated from a config-source or from {@link #systemGetProperty})
     *  pass the value through this method.
     * This will affect the result of {@link #getConfigValue} and
     *  {@link com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfig#get()} and
     *  {@link com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfig.ChangeCallback#configChanged}
     */
    protected String translateConfigValue(@Nonnull String configKey, @Nullable String configValue) {
        return configValue;
    }

    /** Start a thread to periodically reload configs */
    private Thread periodicallyReloadConfigs(String reloadConfigKey, long reloadDefaultValue, TimeUnit reloadTimeUnit) {
        DynamicConfigDuration interval = new DynamicConfigDuration(this, reloadConfigKey, reloadDefaultValue, reloadTimeUnit);
        Thread reloadSourcesThread = new Thread(() -> {
            while (!isClosed) {
                try {
                    interval.sleep(sleepMilliseconds -> Math.max(sleepMilliseconds, MINIMAL_PERIODIC_RELOAD_INTERVAL));
                } catch (InterruptedException ignored) {
                }
                reloadAllConfigs();
            }
        });
        reloadSourcesThread.setName("ConfigManagerReloader");
        reloadSourcesThread.setDaemon(true);
        reloadSourcesThread.start();
        return reloadSourcesThread;
    }

    /** Given a list of changes - log and call change-callbacks */
    private void digestChangeLogs(List<ChangeLog> changeLogs) {

        if (changeLogs.isEmpty()) {
            LOG.info("No configuration changes");
            return;
        }

        // Log all changes

        if (LOG.isInfoEnabled()) {
            StringBuilder changesDescription = new StringBuilder();
            for (ChangeLog changeLog : changeLogs) {
                if ((changeLog.oldEntry != null) && (changeLog.newEntry != null)) {
                    changesDescription.append("\n    Update config: ")
                            .append(Utils.jsonSerializeForLog(changeLog.newEntry.key))
                            .append(" = ")
                            .append(Utils.jsonSerializeForLog(changeLog.newEntry.value))
                            .append(" from ")
                            .append(changeLog.newEntry.describeSource())
                            .append("    Old-value: ")
                            .append(Utils.jsonSerializeForLog(changeLog.oldEntry.value))
                            .append(" from ")
                            .append(changeLog.oldEntry.describeSource());
                } else if (changeLog.newEntry != null) {
                    changesDescription.append("\n       New config: ")
                            .append(Utils.jsonSerializeForLog(changeLog.newEntry.key))
                            .append(" = ")
                            .append(Utils.jsonSerializeForLog(changeLog.newEntry.value))
                            .append(" from ")
                            .append(changeLog.newEntry.describeSource());
                } else if (changeLog.oldEntry != null) {
                    changesDescription.append("\n    Delete config: ")
                            .append(Utils.jsonSerializeForLog(changeLog.oldEntry.key))
                            .append("    Old-value: ")
                            .append(Utils.jsonSerializeForLog(changeLog.oldEntry.value))
                            .append(" from ")
                            .append(changeLog.oldEntry.describeSource());
                }
            }
            LOG.info("{} configurations changed:{}", changeLogs.size(), changesDescription);
        }

        // Call change-callbacks

        callChangeCallbacksNow();
    }

    /** Call all change-callbacks */
    public synchronized void callChangeCallbacksNow() {
        for (Runnable changeCallback : changeCallbacks) {
            try {
                changeCallback.run();
            } catch (Exception exception) {
                LOG.error("Exception in config-change callback: ", exception);
            }
        }
    }

    /**
     * Reload a single config-sources.
     * If the source contains config-keys that are currently set by one of the higherPrioritySources -
     *  then don't override them - UNLESS that higher-priority value is very old (it's generation <= newestObsoleteGeneration).
     */
    private synchronized void reloadConfigSource(
            ConfigProvider.ConfigSource configSource,
            Set<ConfigProvider.ConfigSource> higherPrioritySources,
            long newestObsoleteGeneration,
            List<ChangeLog> changeLogs,
            boolean throwExceptionOnError) {

        lastReloadGeneration++;

        // Query the config-source.
        Collection<ConfigEntry> sourceEntries;
        try {
            sourceEntries = configSource.getConfigEntries();
        } catch (Exception exception) {
            if (throwExceptionOnError) {
                throw new RuntimeException(exception.getMessage(), exception);
            }
            // When a query to a config-source fails, it is possible that the fail is temporary,
            //  so we don't want to remove the source's config-entries, or to override them with lower-priority configs.
            // To do that - we mark as if all existing configs from the failed source are actually reloaded.
            LOG.warn("Failed to query config-source {} (will not override the configs from that source): ", configSource, exception);
            previousConfigs.forEach((oldConfigKey, oldConfigEntry) -> {
                if (oldConfigEntry.sourceSource == configSource) {
                    oldConfigEntry.reloadGeneration = lastReloadGeneration;
                }
            });
            return;
        }

        // Scan queried config-entries.
        for (ConfigEntry newConfigEntry : sourceEntries) {
            String configKey = newConfigEntry.key;
            newConfigEntry.reloadGeneration = lastReloadGeneration;

            // Skip if this config is already set in a higher-priority config-source.
            ConfigEntry oldConfigEntry = previousConfigs.get(configKey);
            if ((oldConfigEntry != null) && higherPrioritySources.contains(oldConfigEntry.sourceSource) && (oldConfigEntry.reloadGeneration > newestObsoleteGeneration)) {
                LOG.debug("Ignoring config {} from {} - due to higher-priority config from {}", Utils.jsonSerializeForLog(newConfigEntry.key), newConfigEntry.sourceSource, oldConfigEntry.sourceSource);
                continue;
            }

            // Update. Note that we want to update even if the value is the same - but the config-source changed.
            previousConfigs.put(configKey, newConfigEntry);

            // Apply change.
            // Only apply configs that are changed in the config-sources:
            //  if a config is unchanged in the config-sources, but is changed by System.setProperty() -
            //  then we don't want to set it. This is why we need previousConfigs.
            if ((oldConfigEntry == null) || (! newConfigEntry.value.equals(oldConfigEntry.value))) {
                // Config is changed, and is different than the system-property - update the system-property.
                systemSetProperty(configKey, newConfigEntry.value);
                changeLogs.add(new ChangeLog(oldConfigEntry, newConfigEntry));
            }
        }
    }

    /** Data about a change of a single config-key */
    private static class ChangeLog {
        final @Nullable ConfigEntry oldEntry;
        final @Nullable ConfigEntry newEntry;

        ChangeLog(@Nullable ConfigEntry oldEntry, @Nullable ConfigEntry newEntry) {
            this.oldEntry = oldEntry;
            this.newEntry = newEntry;
        }
    }
}

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

import com.yahoo.athenz.common.server.util.config.providers.ConfigProvider;
import org.testng.annotations.Test;

import jakarta.annotation.Nullable;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

public class ConfigManagerTest {

    private int changesCount = 0;

    private static class ConfigManagerNoProviders extends ConfigManager {
        @Override
        protected void init() {
        }
    }

    @Test
    public void addRemoveProviderAndSource() {

        ConfigManager configManager = new ConfigManagerNoProviders()
                .addProvider(new TrowingConfigProvider())   // this provider - which always throw - should be ignored
                .registerChangeCallback(() -> {
                    throw new RuntimeException("Change callback throw");
                })   // should be ignored
                .registerChangeCallback(() -> changesCount++);
        assertEquals(configManager.getConfigProviders().length, 1);

        // Add a source - but no provider. Should fail.
        configManager.addConfigSource("mock://abc");
        assertEquals(configManager.getConfigSources().length, 0);

        // Add provider.
        MockConfigProvider mockProvider = new MockConfigProvider();
        configManager.addProvider(mockProvider);
        assertEquals(configManager.getConfigProviders().length, 2);
        assertEquals(configManager.getConfigProviders()[1], mockProvider);

        // Verify not handling empty source-description.
        configManager.addConfigSource("    ");
        assertFalse(mockProvider.triedEmptySourceDescription);

        // Add two sources.
        configManager.addConfigSource("mock://a1b2c3");
        configManager.addConfigSource(new MockConfigProvider.MockConfigSource("mock://aAb2d4", "aAb2d4".toCharArray()));
        assertEquals(configManager.getConfigSources().length, 2);
        MockConfigProvider.MockConfigSource mockSource1 = (MockConfigProvider.MockConfigSource) configManager.getConfigSources()[0];
        MockConfigProvider.MockConfigSource mockSource2 = (MockConfigProvider.MockConfigSource) configManager.getConfigSources()[1];
        assertEquals(mockSource1.sourceDescription, "mock://a1b2c3");
        assertEquals(mockSource2.sourceDescription, "mock://aAb2d4");

        assertEquals(changesCount, 2);
        assertConfigManagerState(configManager,
                "config-test-a -> value-1\n" +
                "config-test-b -> value-2\n" +
                "config-test-c -> value-3\n" +
                "config-test-d -> value-4");
        assertEquals(configManager.getConfigValue("config-test-a"), "value-1");
        assertNull(configManager.getConfigValue("config-test-X"));

        assertTrue(configManager.removeConfigSource("mock://a1b2c3"));
        assertFalse(configManager.removeConfigSource("mock://a1b2c3"));

        assertEquals(changesCount, 3);
        assertConfigManagerState(configManager,
                "config-test-a -> value-A\n" +
                "config-test-b -> value-2\n" +
                "config-test-d -> value-4");

        configManager.addConfigSource("mock://a1b2c3");   // note: now this source is in lower priority
        assertEquals(mockSource2, configManager.getConfigSources()[0]);
        mockSource1 = (MockConfigProvider.MockConfigSource) configManager.getConfigSources()[1];

        assertEquals(changesCount, 4);
        assertConfigManagerState(configManager,
                "config-test-a -> value-A\n" +
                "config-test-b -> value-2\n" +
                "config-test-c -> value-3\n" +
                "config-test-d -> value-4");


        // Delete key "a" from the higher-priority source (currently mockSource2) and verify it is taken from the mockSource1
        // Delete key "b" from all sources
        mockSource2.keysAndValues = "e5d4".toCharArray();
        mockSource1.keysAndValues = "a1c3eE".toCharArray();
        configManager.reloadAllConfigs();
        assertEquals(changesCount, 5);
        assertConfigManagerState(configManager,
                "config-test-a -> value-1\n" +
                "config-test-c -> value-3\n" +
                "config-test-d -> value-4\n" +
                "config-test-e -> value-5");

        // Reload with no change - verify no change callback.
        configManager.reloadAllConfigs();
        assertEquals(changesCount, 5);

        // Temporarily cause the higher-priority source (currently mockSource2) to throw -
        //  and verify that its' configs are not lost or overridden by lowe-priority sources.
        mockSource2.shouldThrow = true;
        configManager.reloadAllConfigs();
        assertEquals(changesCount, 5);
        assertConfigManagerState(configManager,
                "config-test-a -> value-1\n" +
                "config-test-c -> value-3\n" +
                "config-test-d -> value-4\n" +
                "config-test-e -> value-5");

        // Remove the provider - and verify can't add source.
        assertEquals(configManager.getConfigSources().length, 2);
        assertTrue(configManager.removeProvider(mockProvider));
        assertFalse(configManager.removeProvider(mockProvider));
        assertEquals(configManager.getConfigProviders().length, 1);
        configManager.addConfigSource("mock://XXYYZZ");
        assertEquals(configManager.getConfigSources().length, 2);
        assertEquals(changesCount, 5);

        // Add a config-provider that will try to add an already added source.
        configManager.addProvider(new StupidConfigProvider(mockSource2));
        configManager.addConfigSource("mock://a1b2c3");   // source-description already added
        configManager.addConfigSource("something");       // mockSource2 already added
        assertEquals(configManager.getConfigSources().length, 2);
        assertTrue(configManager.removeConfigSource(mockSource2));    // "mock://aAb2d4"
        assertEquals(configManager.getConfigSources().length, 1);
        try {
            configManager.addConfigSource(mockSource2);       // add source that will throw an exception
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "Threw by MockConfigSource");
        }
    }

    @Test
    public void configManagerConstructsWithProviders() {
        // The standard ConfigManager automatically adds standard providers.
        assertTrue(new ConfigManager().getConfigProviders().length > 0);
    }

    /** Describe all configs in a config-manager - a line per config */
    private void assertConfigManagerState(ConfigManager configManager, String expectedDescription) {
        String configDescription = new TreeMap<>(configManager.getAllConfigValues()).entrySet().stream()
                .map(keyValue -> keyValue.getKey() + " -> " + keyValue.getValue())
                .collect(Collectors.joining("\n"));
        assertEquals(configDescription, expectedDescription, "Config-sources status is not as expected");

        StringBuilder systemPropertiesDescription = new StringBuilder();
        for (String systemPropertyName : new TreeSet<>(System.getProperties().stringPropertyNames())) {
            if (systemPropertyName.matches("config-test-.")) {
                if (systemPropertiesDescription.length() > 0) {
                    systemPropertiesDescription.append('\n');
                }
                systemPropertiesDescription.append(systemPropertyName).append(" -> ").append(System.getProperty(systemPropertyName));
            }
        }
        assertEquals(systemPropertiesDescription.toString(), expectedDescription, "System-properties status is not as expected");
    }

    /**
     * For source-description "mock://axbycz", create a source with 3 entries:
     *      config-test-a  ->  value-x
     *      config-test-b  ->  value-y
     *      config-test-c  ->  value-z
     * The source-entries can be changed later.
     */
    private static class MockConfigProvider extends ConfigProvider {
        public boolean triedEmptySourceDescription = false;

        @Override
        public @Nullable
        ConfigSource tryToBuildConfigSource(String sourceDescription) {
            if (sourceDescription.trim().isEmpty()) {
                triedEmptySourceDescription = true;
            }
            Matcher matcher = PROVIDER_DESCRIPTION_PATTERN.matcher(sourceDescription);
            if (matcher.matches()) {
                return new MockConfigSource(sourceDescription, matcher.group(1).toCharArray());
            }
            return null;
        }

        static class MockConfigSource extends ConfigSource {
            /** Come in pairs:   key,value,  key,value,  key,value,  ... */
            public char[] keysAndValues;

            public boolean shouldThrow = false;

            public MockConfigSource(String sourceDescription, char[] keysAndValues) {
                super(sourceDescription);
                this.keysAndValues = keysAndValues;
            }

            @Override
            public Collection<ConfigEntry> getConfigEntries() throws Exception {
                if (shouldThrow) {
                    throw new Exception("Threw by MockConfigSource");
                }

                List<ConfigEntry> entries = new LinkedList<>();
                for (int i = 0; i < keysAndValues.length; i += 2) {
                    entries.add(new ConfigEntry("config-test-" + keysAndValues[i], "value-" + keysAndValues[i + 1], this, null));
                }
                return entries;
            }

            @Override
            public String toString() {
                return "mock-source";
            }
        }
    }

    private static class TrowingConfigProvider extends ConfigProvider {
        @Override
        public @Nullable
        ConfigSource tryToBuildConfigSource(String sourceDescription) throws Exception {
            throw new Exception("Threw by TrowingConfigProvider");
        }
    }

    /** This provider always return the same source */
    private static class StupidConfigProvider extends ConfigProvider {
        public final ConfigSource source;

        public StupidConfigProvider(ConfigSource source) {
            this.source = source;
        }

        @Override
        public @Nullable
        ConfigSource tryToBuildConfigSource(String sourceDescription) {
            return this.source;
        }
    }

    private static final Pattern PROVIDER_DESCRIPTION_PATTERN = Pattern.compile("^mock://(.*)");
}
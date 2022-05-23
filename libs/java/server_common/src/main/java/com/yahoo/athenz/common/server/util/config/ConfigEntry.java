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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * A single configuration entry (immutable).
 * This class should only used by implementors of {@link ConfigProvider}.
 */
public class ConfigEntry {
    public final @Nonnull String key;
    public final @Nonnull String value;
    public final @Nonnull ConfigProvider.ConfigSource sourceSource;

    /**
     * If this is not set, then logs for this config-entry show that this entry originated from some config-source.
     * But this field can, for example, show that this entry originated from specific LINE in a config-file.
     */
    public final @Nullable String sourceDescription;

    /** Used internally by ConfigManager */
    long reloadGeneration;

    public ConfigEntry(
            @Nonnull String key,
            @Nonnull String value,
            @Nonnull ConfigProvider.ConfigSource sourceSource,
            @Nullable String sourceDescription) {
        this.key = key;
        this.value = value;
        this.sourceSource = sourceSource;
        this.sourceDescription = sourceDescription;
    }

    public String describeSource() {
        return (sourceDescription == null) ? sourceSource.toString() : sourceDescription;
    }
}

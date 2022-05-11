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
package com.yahoo.athenz.common.server.util.config.dynamic;

import com.yahoo.athenz.common.server.util.config.ConfigManager;

import jakarta.annotation.Nullable;

/**
 * Holds a string value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 */
public class DynamicConfigString extends DynamicConfig<String> {

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigString(@Nullable String fixedValue) {
        super(fixedValue);
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigString(ConfigManager configManager, String configKey, @Nullable String defaultValue) {
        super(configManager, configKey, defaultValue);
        postConstruction();
    }

    @Override
    protected @Nullable String convertValue(@Nullable String stringValue) {
        return stringValue;
    }

    @Override
    public String toString() {
        return get();
    }
}

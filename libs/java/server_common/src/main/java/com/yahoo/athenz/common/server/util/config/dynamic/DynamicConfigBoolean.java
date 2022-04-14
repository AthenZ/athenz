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

import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.ConfigManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nullable;
import java.lang.invoke.MethodHandles;

/**
 * Holds a boolean value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 * "true"  config-values: true  / yes / on
 * "false" config-values: false / no  / off
 */
public class DynamicConfigBoolean extends DynamicConfig<Boolean> {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigBoolean(@Nullable Boolean fixedValue) {
        super(fixedValue);
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigBoolean(
            ConfigManager configManager,
            String configKey,
            @Nullable Boolean defaultValue) {
        super(configManager, configKey, defaultValue);
        postConstruction();
    }

    @Override
    protected @Nullable Boolean convertValue(@Nullable String stringValue) {
        if (stringValue == null) {
            return null;
        }

        if ("true".equalsIgnoreCase(stringValue) || "yes".equalsIgnoreCase(stringValue) || "on".equalsIgnoreCase(stringValue)) {
            return true;
        } else if ("false".equalsIgnoreCase(stringValue) || "no".equalsIgnoreCase(stringValue) || "off".equalsIgnoreCase(stringValue)) {
            return false;
        } else {
            LOG.warn("Can't convert value of config {} = {} - value has to be boolean (true/yes/on or false/no/off - case insensitive)", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(stringValue));
            return null;
        }
    }

    @Override
    public String toString() {
        Boolean value = get();
        return (value == null) ? null : Boolean.toString(value);
    }
}

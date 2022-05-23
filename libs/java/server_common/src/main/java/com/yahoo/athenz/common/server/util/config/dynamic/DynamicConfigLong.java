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
 * Holds a long value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 */
public class DynamicConfigLong extends DynamicConfig<Long> {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public final long minValue;
    public final long maxValue;

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigLong(@Nullable Long fixedValue) {
        super(fixedValue);
        minValue = Long.MIN_VALUE;
        maxValue = Long.MAX_VALUE;
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigLong(
            ConfigManager configManager,
            String configKey,
            @Nullable Long defaultValue) {
        super(configManager, configKey, defaultValue);
        minValue = Long.MIN_VALUE;
        maxValue = Long.MAX_VALUE;
        postConstruction();
    }

    public DynamicConfigLong(
            ConfigManager configManager,
            String configKey,
            long defaultValue,
            long minValue,
            long maxValue) {
        super(configManager, configKey, defaultValue);
        this.minValue = minValue;
        this.maxValue = maxValue;
        postConstruction();
    }

    @Override
    protected @Nullable Long convertValue(@Nullable String stringValue) {
        if (stringValue == null) {
            return null;
        }
        Long value = null;
        try {
            value = Long.parseLong(stringValue);
        } catch (NumberFormatException ignored) {
        }
        if ((value != null) && ((value < minValue) || (value > maxValue))) {
            value = null;
        }
        if (value == null) {
            LOG.warn("Can't convert value of config {} = {} - value has to be an long between {} and {}", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(stringValue), minValue, maxValue);
        }
        return value;
    }

    @Override
    public String toString() {
        Long value = get();
        return (value == null) ? null : Long.toString(value);
    }
}

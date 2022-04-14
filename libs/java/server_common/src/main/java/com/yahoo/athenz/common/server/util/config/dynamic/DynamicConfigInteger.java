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
 * Holds an integer value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 */
public class DynamicConfigInteger extends DynamicConfig<Integer> {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public final int minValue;
    public final int maxValue;

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigInteger(@Nullable Integer fixedValue) {
        super(fixedValue);
        minValue = Integer.MIN_VALUE;
        maxValue = Integer.MAX_VALUE;
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigInteger(
            ConfigManager configManager,
            String configKey,
            @Nullable Integer defaultValue) {
        super(configManager, configKey, defaultValue);
        minValue = Integer.MIN_VALUE;
        maxValue = Integer.MAX_VALUE;
        postConstruction();
    }

    public DynamicConfigInteger(
            ConfigManager configManager,
            String configKey,
            int defaultValue,
            int minValue,
            int maxValue) {
        super(configManager, configKey, defaultValue);
        this.minValue = minValue;
        this.maxValue = maxValue;
        postConstruction();
    }

    @Override
    protected @Nullable Integer convertValue(@Nullable String stringValue) {
        if (stringValue == null) {
            return null;
        }
        Integer value = null;
        try {
            value = Integer.parseInt(stringValue);
        } catch (NumberFormatException ignored) {
        }
        if ((value != null) && ((value < minValue) || (value > maxValue))) {
            value = null;
        }
        if (value == null) {
            LOG.warn("Can't convert value of config {} = {} - value has to be an integer between {} and {}", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(stringValue), minValue, maxValue);
        }
        return value;
    }

    @Override
    public String toString() {
        Integer value = get();
        return (value == null) ? null : Integer.toString(value);
    }
}

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
 * Holds a double value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 */
public class DynamicConfigDouble extends DynamicConfig<Double> {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public final double minValue;
    public final double maxValue;

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigDouble(@Nullable Double fixedValue) {
        super(fixedValue);
        minValue = Double.MIN_VALUE;
        maxValue = Double.MAX_VALUE;
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigDouble(
            ConfigManager configManager,
            String configKey,
            @Nullable Double defaultValue) {
        super(configManager, configKey, defaultValue);
        minValue = Double.MIN_VALUE;
        maxValue = Double.MAX_VALUE;
        postConstruction();
    }

    public DynamicConfigDouble(
            ConfigManager configManager,
            String configKey,
            double defaultValue,
            double minValue,
            double maxValue) {
        super(configManager, configKey, defaultValue);
        this.minValue = minValue;
        this.maxValue = maxValue;
        postConstruction();
    }

    @Override
    protected @Nullable Double convertValue(@Nullable String stringValue) {
        if (stringValue == null) {
            return null;
        }
        Double value = null;
        try {
            value = Double.parseDouble(stringValue);
        } catch (NumberFormatException ignored) {
        }
        if ((value != null) && ((value < minValue) || (value > maxValue))) {
            value = null;
        }
        if (value == null) {
            LOG.warn("Can't convert value of config {} = {} - value has to be an double between {} and {}", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(stringValue), minValue, maxValue);
        }
        return value;
    }

    @Override
    public String toString() {
        Double value = get();
        return (value == null) ? null : Double.toString(value);
    }
}

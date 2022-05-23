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
 * Holds a float value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 */
public class DynamicConfigFloat extends DynamicConfig<Float> {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public final float minValue;
    public final float maxValue;

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigFloat(@Nullable Float fixedValue) {
        super(fixedValue);
        minValue = Float.MIN_VALUE;
        maxValue = Float.MAX_VALUE;
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfigFloat(
            ConfigManager configManager,
            String configKey,
            @Nullable Float defaultValue) {
        super(configManager, configKey, defaultValue);
        minValue = Float.MIN_VALUE;
        maxValue = Float.MAX_VALUE;
        postConstruction();
    }

    public DynamicConfigFloat(
            ConfigManager configManager,
            String configKey,
            float defaultValue,
            float minValue,
            float maxValue) {
        super(configManager, configKey, defaultValue);
        this.minValue = minValue;
        this.maxValue = maxValue;
        postConstruction();
    }

    @Override
    protected @Nullable Float convertValue(@Nullable String stringValue) {
        if (stringValue == null) {
            return null;
        }
        Float value = null;
        try {
            value = Float.parseFloat(stringValue);
        } catch (NumberFormatException ignored) {
        }
        if ((value != null) && ((value < minValue) || (value > maxValue))) {
            value = null;
        }
        if (value == null) {
            LOG.warn("Can't convert value of config {} = {} - value has to be an float between {} and {}", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(stringValue), minValue, maxValue);
        }
        return value;
    }

    @Override
    public String toString() {
        Float value = get();
        return (value == null) ? null : Float.toString(value);
    }
}

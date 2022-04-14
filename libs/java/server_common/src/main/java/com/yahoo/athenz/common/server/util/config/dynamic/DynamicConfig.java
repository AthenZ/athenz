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

import com.fasterxml.jackson.annotation.JsonGetter;
import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.ConfigManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.Closeable;
import java.lang.invoke.MethodHandles;
import java.util.HashSet;
import java.util.Set;

/**
 * Holds the value for some config-key - always up-to-date.
 * Getting the value is very cheap (performance-wise).
 * Class T must properly support {@link Object#equals(Object)}.
 */
public abstract class DynamicConfig<T> implements Closeable {

    public final ConfigManager configManager;
    public final String configKey;
    public final @Nullable T defaultValue;
    private @Nullable T value;
    private final Runnable mainChangeCallback;
    private final Set<ChangeCallback<T>> changeCallbacks = new HashSet<>();

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** @see #registerChangeCallback(ChangeCallback)  */
    public interface ChangeCallback<T> {
        void configChanged(T newValue, T oldValue, DynamicConfig<T> dynamicConfig);
    }

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfig(@Nullable T fixedValue) {
        this.configManager = null;
        this.configKey = null;
        this.defaultValue = fixedValue;
        this.value = fixedValue;
        this.mainChangeCallback = null;
    }

    /** Construct a dynamic value - that may automatically change */
    public DynamicConfig(ConfigManager configManager, String configKey, @Nullable T defaultValue) {
        this.configManager = configManager;
        this.configKey = configKey;
        this.defaultValue = defaultValue;
        this.mainChangeCallback = this::resetValue;
        configManager.registerChangeCallback(mainChangeCallback);
    }

    /** This must be called at construction (only for dynamic - not for fixed) - once {@link #convertValue} can be called */
    protected void postConstruction() {
        resetValue();
    }

    /** Get the up-to-date value */
    @JsonGetter
    public T get() {
        return value;
    }

    /** Whenever this config change in the config-sources - call this callback */
    public synchronized void registerChangeCallback(@Nonnull ChangeCallback<T> changeCallback) {
        changeCallbacks.add(changeCallback);
    }

    /** Undo a call to {@link #registerChangeCallback} */
    public synchronized boolean unregisterChangeCallback(@Nonnull ChangeCallback<T> changeCallback) {
        return changeCallbacks.remove(changeCallback);
    }

    /** Call all change-callbacks */
    public synchronized void callChangeCallbacksNow(T oldValue) {
        for (ChangeCallback<T> callback : changeCallbacks) {
            try {
                callback.configChanged(value, oldValue, this);
            } catch (Exception exception) {
                LOG.warn("Exception in dynamic-config {} change-callback.    Old value: {}    New value: {}    Exception: ", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(oldValue), Utils.jsonSerializeForLog(value), exception);
            }
        }
    }

    /** Inner value will no longer be updated, and change-callbacks will no longer be called */
    @Override
    public void close() {
        if (configManager != null) {
            configManager.unregisterChangeCallback(mainChangeCallback);
        }
    }

    /**
     * Convert a config-value as was read from {@link System#getProperty} into class T.
     * Note that the string-value may be null.
     * Returning null is equivalent to returning {@link #defaultValue}.
     * In case of error - either throw or return null/{@link #defaultValue}.
     */
    protected abstract @Nullable T convertValue(@Nullable String stringValue) throws Exception;

    /** Config value MIGHT have been changed - adapt */
    private synchronized void resetValue() {
        // Convert value to type T.
        String stringValue = configManager.getConfigValue(configKey);
        T value;
        try {
            value = convertValue(stringValue);
        } catch (Exception exception) {
            LOG.warn("Can't convert value of config {} = {} for class {}", Utils.jsonSerializeForLog(configKey), Utils.jsonSerializeForLog(stringValue), this.getClass());
            value = this.value;   // keep existing value
        }
        if (value == null) {
            value = defaultValue;
        }

        // Call change-callbacks.
        if (((this.value != null) && (value == null)) || ((this.value == null) && (value != null)) || ((this.value != null) && (! this.value.equals(value)))) {
            T oldValue = this.value;
            this.value = value;
            callChangeCallbacksNow(oldValue);
        }
    }
}

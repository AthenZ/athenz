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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nullable;
import java.lang.invoke.MethodHandles;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * Holds a duration value for some config-key - always up-to-date.
 * This class can be asked to sleep for the configured duration - with the nice feature that
 *  the sleep can be cut-short or prolonged if the configuration is dynamically changed.
 */
public class DynamicConfigDuration extends DynamicConfigLong {

    public final TimeUnit configTimeUnit;

    /**
     * Calling {@link #sleep()} is slightly more expensive than calling {@link Thread#sleep(long)}.
     * When sleeping for short durations (less than SHORT_SLEEP_DURATION_MILLISECONDS),
     *  where it is unlikely/unimportant to adjust to configuration changes -
     *  {@link #sleep()} will simply call {@link Thread#sleep(long)}.
     */
    public static long SHORT_SLEEP_DURATION_MILLISECONDS = 10000;

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** Construct a non-dynamic fixed value - that will never change */
    public DynamicConfigDuration(long fixedValue, TimeUnit configTimeUnit) {
        super(fixedValue);
        this.configTimeUnit = configTimeUnit;
    }

    /**
     * Construct a dynamic value - that may automatically change.
     * @param configTimeUnit the time-unit of the config-value.
     *   For example, if this is {@link TimeUnit#SECONDS}, and the config-value is "5" - then {@link #getMilliseconds()} would return 5000.
     */
    public DynamicConfigDuration(
            ConfigManager configManager,
            String configKey,
            long defaultValue,
            TimeUnit configTimeUnit) {
        super(configManager, configKey, defaultValue, 0, Long.MAX_VALUE);
        this.configTimeUnit = configTimeUnit;
    }

    /** Get the up-to-date value - converted to milliseconds */
    public long getMilliseconds() {
        Long value = super.get();
        if (value == null) {
            throw new RuntimeException("DynamicConfigDuration.get() returned null - this is unexpected");
        }
        return configTimeUnit.toMillis(value);
    }

    /**
     * Sleep according to the config-value - like {@link Thread#sleep(long)}.
     * If the config-value is changed while sleeping - then the sleeping is adjusted.
     */
    public void sleep() throws InterruptedException {
        this.sleep(null);
    }

    /**
     * Like {@link #sleep()} - but with some arbitrary "translation" of the return value of {@link #getMilliseconds()}.
     * Example: sleep the configured time - but at least one second:   {@code   sleep(sleepMilliseconds -> Math.max(sleepMilliseconds, 1000L)) }
     * Example: sleep the configured time - minus 1 second:            {@code   sleep(sleepMilliseconds -> sleepMilliseconds - 1000L) }
     */
    public void sleep(@Nullable Function<Long, Long> translateSleepTime) throws InterruptedException {

        // Simpler handling for short durations.
        long sleepMilliseconds = getMilliseconds();
        if (sleepMilliseconds <= SHORT_SLEEP_DURATION_MILLISECONDS) {
            Thread.sleep(sleepMilliseconds);
            return;
        }

        // Register a change-callback to reset the sleep if the config value changes.
        Object lock = new Object();
        ChangeCallback<Long> callback = (newValue, oldValue, dynamicConfig) -> {
            synchronized (lock) {
                LOG.trace("DynamicConfigDuration<{}>.sleep: config changed whilst sleeping:   {}  -->  {}", configKey, oldValue, newValue);
                lock.notify();
            }
        };
        registerChangeCallback(callback);

        long startTime = 0;
        try {
            synchronized (lock) {
                while (true) {
                    long currentTime = System.currentTimeMillis();
                    if (startTime == 0) {
                        startTime = currentTime;
                    }
                    long overallSleepMilliseconds = getMilliseconds();
                    if (translateSleepTime != null) {
                        overallSleepMilliseconds = translateSleepTime.apply(overallSleepMilliseconds);
                    }
                    long timeLeft = overallSleepMilliseconds - (currentTime - startTime);
                    if (timeLeft <= 0) {
                        break;
                    }

                    LOG.trace("DynamicConfigDuration<{}>.sleep: sleeping {} ms", configKey, timeLeft);
                    lock.wait(timeLeft);
                }
            }
        } finally {
            unregisterChangeCallback(callback);
        }
    }

    /** Like {@link #sleep()} - only when {@link InterruptedException} happens - stop the sleep and don't throw */
    public void sleepAndStopOnInterrupt() {
        try {
            sleep();
        } catch (InterruptedException ignored) {
            LOG.trace("DynamicConfigDuration: Sleep interrupted");
        }
    }

    /** Like {@link #sleep(Function)} - only when {@link InterruptedException} happens - stop the sleep and don't throw */
    public void sleepAndStopOnInterrupt(@Nullable Function<Long, Long> translateSleepTime) {
        try {
            sleep(translateSleepTime);
        } catch (InterruptedException ignored) {
            LOG.trace("DynamicConfigDuration: Sleep interrupted");
        }
    }
}

/*
 * Copyright The Athenz Authors
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
package com.yahoo.athenz.zms;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.ZMSConsts.*;

/**
 * This class creates a background daemon that periodically verifies our
 * database connectivity by listing the system (sys.auth) domains and stores
 * the result in a volatile flag. The getStatus handler only needs to read
 * that flag instead of making a database call on every request, thus keeping
 * the status endpoint as fast as possible.
 */
public class DBHealthChecker {

    private static final Logger LOGGER = LoggerFactory.getLogger(DBHealthChecker.class);

    private static final String SYS_AUTH = "sys.auth";

    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private volatile boolean domainsAvailable = false;

    public DBHealthChecker(final DBService dbService) {
        LOGGER.info("Initializing DBHealthChecker...");
        this.dbService = dbService;

        // run the check once synchronously so the flag reflects the current
        // state of the database by the time the server starts serving requests

        checkDomainsAvailability();

        // only in case of test invocation we don't need to start the timer task

        if (shouldDisableTimerTask()) {
            LOGGER.info("Timer task is not started because {} is set to true",
                    ZMS_PROP_DB_HEALTH_CHECK_DISABLE_TIMER);
            return;
        }
        init();
    }

    private boolean shouldDisableTimerTask() {
        return Boolean.parseBoolean(System.getProperty(ZMS_PROP_DB_HEALTH_CHECK_DISABLE_TIMER, "false"));
    }

    /**
     * Create the scheduler that refreshes the domains availability flag
     */
    private void init() {
        scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        long frequencySeconds = Long.parseLong(
                System.getProperty(ZMS_PROP_DB_HEALTH_CHECK_FREQUENCY_SECONDS,
                        ZMS_PROP_DB_HEALTH_CHECK_FREQUENCY_DEFAULT));
        scheduledExecutor.scheduleAtFixedRate(this::checkDomainsAvailability, frequencySeconds,
                frequencySeconds, TimeUnit.SECONDS);
    }

    /**
     * Shutdown hook for the scheduler
     */
    public void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    /**
     * This method gets called on server start up as well as every configured
     * time period. It verifies our database connectivity by listing the system
     * domains and updates the domainsAvailable flag accordingly. Any failure
     * (empty result or an exception) results in the flag being set to false.
     */
    void checkDomainsAvailability() {
        try {
            domainsAvailable = !dbService.listDomains(SYS_AUTH, 0, false).isEmpty();
        } catch (Exception ex) {
            LOGGER.error("Unable to verify database connectivity: {}", ex.getMessage());
            domainsAvailable = false;
        }
    }

    /**
     * @return true if the system domains were available as of the last check
     */
    public boolean isDomainsAvailable() {
        return domainsAvailable;
    }
}

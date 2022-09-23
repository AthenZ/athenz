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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.ZMSConsts.*;

/**
 * This class creates a background daemon to periodically download
 * current state of principals from configured Principal Authority and facilitates changes
 * in role and group memberships based on that.
 */
public class PrincipalStateUpdater {
    private static final Logger LOGGER = LoggerFactory.getLogger(PrincipalStateUpdater.class);
    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private final Authority principalAuthority;

    public PrincipalStateUpdater(final DBService dbService, final Authority principalAuthority) {
        LOGGER.info("initializing PrincipalStateUpdater to periodically refresh user state from Authority");

        this.dbService = dbService;
        this.principalAuthority = principalAuthority;
        refreshPrincipalStateFromAuthority();

        // Only in case of test invocation we don't need to start the timer task.

        if (shouldDisableTimerTask()) {
            LOGGER.info("Time task is not started because athenz.zms.disable_principal_state_updater_timer_task is set to true");
            return;
        }
        init();
    }

    private boolean shouldDisableTimerTask() {
        return Boolean.parseBoolean(System.getProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "false"));
    }

    /**
     * Create the Scheduler
    */
    private void init() {
        scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        long principalStateUpdaterFrequency = Long.parseLong(
                System.getProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_FREQUENCY, ZMS_PROP_PRINCIPAL_STATE_UPDATER_FREQUENCY_DEFAULT));
        scheduledExecutor.scheduleAtFixedRate(this::refreshPrincipalStateFromAuthority, principalStateUpdaterFrequency,
                principalStateUpdaterFrequency, TimeUnit.MINUTES);
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
     * This method gets called on server start up as well as every configured time period.
     * It retrieves list of Principals from User Authority and toggles their state in DB
     * based on latest state.
     */
    void refreshPrincipalStateFromAuthority() {

        if (principalAuthority == null) {
            return;
        }

        // First lets get a list of users by system disabled state from authority

        List<Principal> newSystemDisabledPrincipals = principalAuthority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED));
        LOGGER.info("Found suspendedPrincipals={} from Principal Authority", newSystemDisabledPrincipals);

        // Then get a list of system disabled principals from DB

        List<Principal> existingSystemDisabledPrincipals = dbService.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue());
        LOGGER.info("Found existingSystemDisabledPrincipals={} from DB", existingSystemDisabledPrincipals);

        // To find out the new system disabled principals, lets remove the ones which are already marked as system disabled in DB

        List<Principal> suspendedPrincipals = new ArrayList<>(newSystemDisabledPrincipals);
        suspendedPrincipals.removeAll(existingSystemDisabledPrincipals);

        // Update new system disabled in DB

        dbService.updatePrincipalByStateFromAuthority(suspendedPrincipals, true);
        LOGGER.info("Updated newSystemDisabledPrincipals={} in DB", suspendedPrincipals);

        // Now let's re-activate existing system disabled which are not present in new list

        List<Principal> reEnabledPrincipals = new ArrayList<>(existingSystemDisabledPrincipals);
        reEnabledPrincipals.removeAll(newSystemDisabledPrincipals);

        // Revert back system disabled state in DB

        dbService.updatePrincipalByStateFromAuthority(reEnabledPrincipals, false);
        LOGGER.info("Updated reEnabledPrincipals={} in DB", reEnabledPrincipals);
    }
}

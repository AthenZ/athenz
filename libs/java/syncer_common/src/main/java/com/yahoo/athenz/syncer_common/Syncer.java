/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer_common;

import java.util.function.BiFunction;

public class Syncer {

    /**
    * Run a one time sync.
     * @param syncer - A class that syncs data
     * @param syncFunction - A syncing function that take a time range and return
     *                     true if the sync was successful or false if it failed
     */
    public <T> void sync(T syncer, BiFunction<T, SyncTimeRange, Boolean> syncFunction) {
        // Init StatusSender
        StatusSender statusSender = getStatusSender();

        // Init SyncerStore
        SyncerStore syncerStore = new SyncerStore();
        if (syncerStore.stopFileExists()) {
            statusSender.sendStatusAndExit(SyncerConsts.STOP_FILE_EXISTS_MESSAGE);
        }

        // Get sync time range
        Long endTime = System.currentTimeMillis();
        Long startTime = syncerStore.getLastRunTime();

        SyncTimeRange syncTimeRange = new SyncTimeRange(startTime, endTime);
        Boolean syncSuccessful = syncFunction.apply(syncer, syncTimeRange);
        if (syncSuccessful) {
            syncerStore.setLastSuccessfulRunTimestamp(String.valueOf(syncTimeRange.getEndTime()));
        } else {
            statusSender.sendStatusAndExit(SyncerConsts.SYNC_FAILED_START_SAME_SPOT);
        }
    }

    /**
     * Load StatusSender implementaton
     */
    private StatusSender getStatusSender() {
        String statusSenderClass = System.getProperty(SyncerConsts.PROP_STATUS_SENDER_FACTORY_CLASS,
                SyncerConsts.DEFAULT_STATUS_SENDER_FACTORY_CLASS);
        StatusSenderFactory statusSenderFactory;
        try {
            statusSenderFactory = (StatusSenderFactory) Class.forName(statusSenderClass).getDeclaredConstructor().newInstance();
            return statusSenderFactory.create();
        } catch (Exception ex) {
            System.out.println("Invalid StatusSenderFactory class: " + statusSenderClass + " error: " + ex);
            System.exit(1);
        }
        return null;
    }
}

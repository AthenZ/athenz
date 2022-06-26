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

import java.util.Date;

public class SyncTimeRange {
    private Long startTime;

    private Long endTime;

    public SyncTimeRange(Long startTime, Long endTime) {
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public Long getStartTime() {
        return startTime;
    }

    public Long getEndTime() {
        return endTime;
    }

    public void setStartTime(Long startTime) {
        this.startTime = startTime;
    }

    public void setEndTime(Long endTime) {
        this.endTime = endTime;
    }

    @Override
    public String toString() {
        Date startTimeDate = new Date(startTime);
        Date endTimeDate = new Date(endTime);
        return "Start: " + startTimeDate + ", End: " + endTimeDate;
    }
}

/*
 * Copyright 2020 Verizon Media
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
import moment from 'moment-timezone';

class DateUtils {
    constructor() {
        this.dateFormat = 'YYYY-MM-DD HH:mm zz';
    }

    getLocalDate(currentDate, currentTimezone, newTimezone) {
        return moment(currentDate, 'YYYY-MM-DDTHH:mm:ss.SSSZ', currentTimezone)
            .tz(newTimezone)
            .format(this.dateFormat);
    }

    getUTCDate(currentDate, currentTimezone) {
        return this.getLocalDate(currentDate, currentTimezone, 'UTC');
    }

    getDatePlusFourHours(currentDate, currentTimezone) {
        let currDt = new Date();
        currDt.setHours(currentDate.getHours() + 4);
        return this.getLocalDate(currDt, currentTimezone, 'UTC');
    }

    getCurrentTimeZone() {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    }

    // converts a datetime returned by the datetime picker into an
    // RDL "Timestamp" (e.g. "2018-10-09T22:55:57.389Z")
    uxDatetimeToRDLTimestamp(ux) {
        if (ux) {
            return new Date(ux).toISOString();
        }
        return '';
    }
}

export default DateUtils;

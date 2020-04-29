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
import React from 'react';
import DateUtils from '../../../components/utils/DateUtils';

describe('LocalDate', () => {
    it('should test', () => {
        let originalDate = '2020-02-12T21:44:37.792Z';
        let localDate = new DateUtils();
        let modifiedDate = localDate.getLocalDate(
            originalDate,
            'UTC',
            'America/Los_Angeles'
        );
        let reversedOriginalDate = localDate.getUTCDate(originalDate, 'UTC');
        expect(modifiedDate).toEqual('2020-02-12 13:44 PST');
        expect(reversedOriginalDate).toEqual('2020-02-12 21:44 UTC');
    });
});

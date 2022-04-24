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

import React from 'react';
import RegexUtils from '../../../components/utils/RegexUtils';
import {
    MICROSEGMENTATION_SERVICE_NAME_REGEX,
    StaticWorkloadType,
} from '../../../components/constants/constants';

describe('RegexUtils', () => {
    it('should test regex pattern match', () => {
        expect(
            RegexUtils.validate('a.b.c.d', StaticWorkloadType[0].pattern)
        ).toEqual(true);
        expect(
            RegexUtils.validate('a.b.c.**', StaticWorkloadType[0].pattern)
        ).toEqual(false);
        expect(
            RegexUtils.validate('a.(.c.d', StaticWorkloadType[0].pattern)
        ).toEqual(false);

        expect(
            RegexUtils.validate('a:b:c_asd_9892', StaticWorkloadType[1].pattern)
        ).toEqual(true);
        expect(
            RegexUtils.validate('a:b:c_asd.9892', StaticWorkloadType[1].pattern)
        ).toEqual(false);

        expect(
            RegexUtils.validate('10.8.9.9', StaticWorkloadType[4].pattern)
        ).toEqual(true);
        expect(
            RegexUtils.validate('a.8.9.9', StaticWorkloadType[4].pattern)
        ).toEqual(null);
        expect(
            RegexUtils.validate(
                'domain:group.member',
                MICROSEGMENTATION_SERVICE_NAME_REGEX
            )
        ).toEqual(false);
        expect(
            RegexUtils.validate('*', MICROSEGMENTATION_SERVICE_NAME_REGEX)
        ).toEqual(true);
        expect(
            RegexUtils.validate(
                'domain.service',
                MICROSEGMENTATION_SERVICE_NAME_REGEX
            )
        ).toEqual(true);
    });
});

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
import GroupRow from '../../../components/group/GroupRow';
import { colors } from '../../../components/denali/styles';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('GroupRow', () => {
    it('should render', () => {
        const details = {
            name: 'athens:group.testui',
            modified: '2017-08-03T18:44:41.867Z',
        };
        const domain = 'domain';
        const color = colors.row;
        const idx = '50';
        const timeZone = 'UTC';

        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <GroupRow
                        details={details}
                        domain={domain}
                        color={color}
                        idx={idx}
                        timeZone={timeZone}
                    />
                </tbody>
            </table>
        );
        const roleRow = getByTestId('group-row');

        expect(roleRow).toMatchSnapshot();
    });
});

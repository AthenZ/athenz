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
import { render } from '@testing-library/react';
import InstanceRow from '../../../components/service/InstanceRow';
import { colors } from '../../../components/denali/styles';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('GroupRow', () => {
    it('should render', () => {
        let details = {
            domainName: null,
            serviceName: null,
            uuid: 'instance-id-aws-1',
            ipAddresses: ['10.3.1.1'],
            provider: 'aws',
            updateTime: '2021-03-28T21:38:26.983Z',
        };

        let domain = 'domain';
        let color = colors.row;
        let idx = '50';

        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <InstanceRow
                        details={details}
                        domain={domain}
                        color={color}
                        idx={idx}
                    />
                </tbody>
            </table>
        );
        const instanceRow = getByTestId('instance-row');

        expect(instanceRow).toMatchSnapshot();
    });
});

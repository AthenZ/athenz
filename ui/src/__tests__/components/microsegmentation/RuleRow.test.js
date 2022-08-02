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
import { colors } from '../../../components/denali/styles';
import RuleRow from '../../../components/microsegmentation/RuleRow';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('RuleRow', () => {
    it('should render', () => {
        let details = {
            source_service: 'serviceA',
            source_port: '1111',
            destination_port: '2222',
            destination_services: ['serviceB', 'serviceC', 'serviceD'],
            layer: 'tcp',
        };
        let domain = 'domain';
        let role = 'roleName';
        let color = colors.row;
        let idx = '50';
        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <RuleRow
                        category={'inbound'}
                        domain={domain}
                        details={details}
                        idx={idx}
                        color={color}
                        key={idx}
                        _csrf={'_csrf'}
                    />
                </tbody>
            </table>
        );
        const ruleRow = getByTestId('segmentation-row');

        expect(ruleRow).toMatchSnapshot();
    });
});

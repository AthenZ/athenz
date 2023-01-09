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
import RolePolicyRuleTable from '../../../components/role-policy/RolePolicyRuleTable';
import {
    buildPoliciesForState,
    getStateWithPolicies,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';

describe('PolicyRuleTable', () => {
    it('should render', () => {
        const domain = 'home.pgote';
        const policyName = 'test';
        const policies = buildPoliciesForState(
            {
                [`${domain}:policy.${policyName}:0`]: {
                    name: `${domain}:policy.${policyName}`,
                    modified: '2022-07-13T09:48:22.510Z',
                    version: '0',
                    active: true,
                    assertions: {
                        11921: {
                            role: 'home.pgote:role.allunixusers',
                            resource: 'home.pgote:aaaa',
                            action: 'aaa',
                            effect: 'ALLOW',
                            id: 11921,
                        },
                    },
                },
            },
            domain
        );

        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <RolePolicyRuleTable
                            showTable={true}
                            color={'white'}
                            number={0}
                            domain={domain}
                            name={policyName}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithPolicies(policies)
        );
        const ruleTable = getByTestId('role-policy-rule-table');
        expect(ruleTable).toMatchSnapshot();
    });

    it('should render empty', () => {
        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <RolePolicyRuleTable
                            showTable={false}
                            color={'white'}
                            number={0}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const ruleTable = null;
        expect(ruleTable).toMatchSnapshot();
    });
});

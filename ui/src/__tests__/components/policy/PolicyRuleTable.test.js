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
import { render } from '@testing-library/react';
import PolicyRuleTable from '../../../components/policy/PolicyRuleTable';

describe('PolicyRuleTable', () => {
    it('should render', () => {
        const assertions = [
            {
                role: 'home.pgote:role.allunixusers',
                resource: 'home.pgote:aaaa',
                action: 'aaa',
                effect: 'ALLOW',
                id: 11921,
            },
        ];
        const { getByTestId } = render(
            <table>
                <tbody>
                    <tr>
                        <PolicyRuleTable
                            showTable={true}
                            color={'white'}
                            number={0}
                            assertions={assertions}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const ruleTable = getByTestId('ruletable');
        expect(ruleTable).toMatchSnapshot();
    });

    it('should render empty', () => {
        const assertions = [];
        const { getByTestId } = render(
            <table>
                <tbody>
                    <tr>
                        <PolicyRuleTable
                            showTable={false}
                            color={'white'}
                            number={0}
                            assertions={assertions}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const ruleTable = null;
        expect(ruleTable).toMatchSnapshot();
    });

    it('should render', () => {
        const assertions = [
            {
                role: 'home.pgote:role.allunixusers',
                resource: 'home.pgote:aaaa',
                action: 'aaa',
                effect: 'ALLOW',
                id: 11921,
            },
        ];
        const { getByTestId } = render(
            <table>
                <tbody>
                    <tr>
                        <PolicyRuleTable
                            showTable={true}
                            color={'white'}
                            number={0}
                            assertions={assertions}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const ruleTable = getByTestId('ruletable');
        expect(ruleTable).toMatchSnapshot();
    });
});

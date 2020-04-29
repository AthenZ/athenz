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
import PolicyRow from '../../../components/policy/PolicyRow';
import { colors } from '../../../components/denali/styles';

describe('PolicyRow', () => {
    it('should render', () => {
        const color = colors.row;
        const name = 'sections';
        const api = {
            getPolicy(domain) {
                return new Promise((resolve, reject) => {
                    resolve(['a, b']);
                });
            },
        };
        const { getByTestId } = render(
            <table>
                <tbody>
                    <PolicyRow name={name} color={color} api={api} />
                </tbody>
            </table>
        );
        const policyRow = getByTestId('policy-row');
        expect(policyRow).toMatchSnapshot();
    });
});

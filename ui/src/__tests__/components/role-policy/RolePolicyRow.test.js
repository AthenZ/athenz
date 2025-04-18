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
import RolePolicyRow from '../../../components/role-policy/RolePolicyRow';
import { colors } from '../../../components/denali/styles';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('RolePolicyRow', () => {
    it('should render', () => {
        const color = colors.row;
        const name = 'sections';
        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <RolePolicyRow name={name} color={color} />
                </tbody>
            </table>
        );
        const rolePolicyRow = getByTestId('policy-row');
        expect(rolePolicyRow).toMatchSnapshot();
    });
});

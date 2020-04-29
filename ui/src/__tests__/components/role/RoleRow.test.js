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
import RoleRow from '../../../components/role/RoleRow';
import { colors } from '../../../components/denali/styles';

describe('RoleRow', () => {
    it('should render', () => {
        let details = {
            name: 'athens:role.ztssia_cert_rotate',
            modified: '2017-08-03T18:44:41.867Z',
        };
        let domain = 'domain';
        let color = colors.row;
        let idx = '50';
        const { getByTestId } = render(
            <table>
                <tbody>
                    <RoleRow
                        details={details}
                        domain={domain}
                        color={color}
                        idx={idx}
                    />
                </tbody>
            </table>
        );
        const roleRow = getByTestId('role-row');

        expect(roleRow).toMatchSnapshot();
    });
});

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
import RoleMemberReviewDetails from '../../../components/role/RoleMemberReviewDetails';
import { colors } from '../../../components/denali/styles';

describe('RoleMemberReviewDetails', () => {
    it('should render', () => {
        let color = colors.row;
        let domain = 'domain';
        let role = 'role';

        const api = {
            getRole(domain) {
                return new Promise((resolve, reject) => {
                    let role = {
                        roleMembers: [{ memberName: 'a' }, { memberName: 'b' }],
                        memberExpiryDays: 30,
                        serviceExpiryDays: 20,
                    };
                    resolve(['a, b']);
                });
            },
        };

        const { getByTestId } = render(
            <table>
                <tbody>
                    <tr>
                        <RoleMemberReviewDetails
                            color={color}
                            domain={domain}
                            role={role}
                            api={api}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const auditLogList = getByTestId('review-member-list');

        expect(auditLogList).toMatchSnapshot();
    });
});

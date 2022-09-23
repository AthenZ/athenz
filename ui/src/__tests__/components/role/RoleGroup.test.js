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
import RoleGroup from '../../../components/role/RoleGroup';

describe('RoleGroup', () => {
    it('should render', () => {
        let details = {
            name: 'athens:role.ztssia_cert_rotate',
            modified: '2017-08-03T18:44:41.867Z',
        };
        let name = 'AWS';
        let domain = 'domain';
        let roles = [];
        let role1 = {
            name: 'domain:role.role1',
            roleMembers: [
                { memberName: 'user.test1' },
                { memberName: 'user.test2' },
            ],
            memberExpiryDays: 30,
            serviceExpiryDays: 20,
            memberReviewDays: 70,
            serviceReviewDays: 80,
        };
        let role2 = {
            name: 'domain:role.role2',
            roleMembers: [
                { memberName: 'user.test3' },
                { memberName: 'user.test4' },
            ],
            memberExpiryDays: null,
            serviceExpiryDays: 20,
            memberReviewDays: 30,
            serviceReviewDays: null,
        };
        roles.push(role1);
        roles.push(role2);

        const { getByTestId } = render(
            <table>
                <tbody>
                    <RoleGroup
                        details={details}
                        domain={domain}
                        name={name}
                        roles={roles}
                    />
                </tbody>
            </table>
        );
        const roleGroup = getByTestId('role-group');

        expect(roleGroup).toMatchSnapshot();
    });
    it('should render empty', () => {
        let details = {
            name: 'athens:role.ztssia_cert_rotate',
            modified: '2017-08-03T18:44:41.867Z',
        };
        let name = 'AWS';
        let domain = 'domain';
        let roles = [];
        const { getByTestId } = render(
            <table>
                <tbody>
                    <RoleGroup
                        details={details}
                        domain={domain}
                        name={name}
                        roles={roles}
                    />
                </tbody>
            </table>
        );
        const roleGroup = null;
        expect(roleGroup).toMatchSnapshot();
    });
});

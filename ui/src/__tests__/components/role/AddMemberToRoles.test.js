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
import AddMemberToRoles from '../../../components/role/AddMemberToRoles';
import API from '../../../api';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

describe('AddMemberToRoles', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', () => {
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
        let roleMembers = [];
        let roleMember1 = {
            memberName: 'user.test1',
            memberRoles: [
                {
                    roleName: 'role1',
                },
            ],
            memberFullName: null,
        };
        roleMembers.push(roleMember1);
        let roleMember2 = {
            memberName: 'user.test2',
            memberRoles: [
                {
                    roleName: 'role1',
                },
            ],
            memberFullName: null,
        };
        roleMembers.push(roleMember2);
        let roleMember3 = {
            memberName: 'user.test3',
            memberRoles: [
                {
                    roleName: 'role2',
                },
            ],
            memberFullName: null,
        };
        roleMembers.push(roleMember3);
        let roleMember4 = {
            memberName: 'user.test4',
            memberRoles: [
                {
                    roleName: 'role2',
                },
            ],
            memberFullName: null,
        };
        roleMembers.push(roleMember4);

        MockApi.setMockApi({
            getRoles: jest.fn().mockReturnValue(Promise.resolve(roles)),
            getRoleMembers: jest
                .fn()
                .mockReturnValue(Promise.resolve(roleMembers)),
        });
        const onCancelMock = jest.fn();
        roles.push(role1);
        roles.push(role2);

        const { getByTestId } = renderWithRedux(
            <AddMemberToRoles
                domain={domain}
                // roles={roles}
                justificationRequired={true}
                onCancel={onCancelMock}
            />
        );
        const roleMemberForm = getByTestId('add-member-to-roles-form');
        expect(roleMemberForm).toMatchSnapshot();
    });
});

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
import { render, waitFor } from '@testing-library/react';
import UserRoleTable from '../../../components/role/UserRoleTable';
import API from '../../../api';
import { buildRolesForState, getStateWithRoles, renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

//TODO roy - failed because extra 3 divs
describe('UserRoleTable', () => {
    it('should render', async () => {
        let domain = 'athens';
        const roles = buildRolesForState({
            'role1': {
                name: 'role1',
                roleMembers: {
                    'user.test1': {
                        memberName: 'user.test1',
                        memberFullName: 'testing1',
                    }
                }
            },
            'role2': {
                name: 'role2',
                roleMembers: {
                    'user.test2': {
                        memberName: 'user.test2',
                        memberFullName: 'testing2',
                    },
                }
            }
        } ,domain)

        const { getByTestId, queryByText } = renderWithRedux(
            <UserRoleTable
                domain={domain}
                searchText={'test'}
            />,
            getStateWithRoles(roles)
        );
        await waitFor(() => {
            expect(queryByText('test'));
        });

        const userroletable = getByTestId('userroletable');

        expect(userroletable).toMatchSnapshot();
    });
});

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
import {render, waitFor} from '@testing-library/react';
import UserRoleTable from '../../../components/role/UserRoleTable';
import API from '../../../api';

describe('UserRoleTable', () => {
    it('should render', async () => {
        let domain = 'athens';
        let roles = [];
        let role1 = {
            name: 'a',
        };
        let role2 = {
            name: 'b',
        };
        roles.push(role1);
        roles.push(role2);
        const api = {
            getRoleMembers(domain) {
                return new Promise((resolve, reject) => {
                    // reject({
                    //     statusCode: 500,
                    //     body: {
                    //         message: "Test error"
                    //     }
                    // });
                    let member = {
                        members: [
                            {
                                memberName: "user.test1",
                                memberRoles: ['role1'],
                                memberFullName: 'testing1'
                            },
                            {
                                memberName: "user.test2",
                                memberRoles: ['role2'],
                                memberFullName: 'testing2'
                            }
                        ],
                    };
                    resolve(member)
                });
            },
        };

        // for (let i = 0; i < members.members.length; i++) {
        //                     let name = members.members[i].memberName;
        //                     expand[name] = members.members[i].memberRoles;
        //                     fullNameArr[name] = members.members[i].memberFullName;
        //                     contents[name] = null;
        //                     expandArray[name] = false;
        //                 }

        const {getByTestId, queryByText} = render(
            <UserRoleTable roles={roles} api={api} domain={domain} searchText={'test'}/>
        );
        await waitFor(() => {
            expect(queryByText("test"));
        });

        const userroletable = getByTestId('userroletable');

        expect(userroletable).toMatchSnapshot();
    });
});

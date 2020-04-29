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
import UserRoleTable from '../../../components/role/UserRoleTable';
import API from '../../../api';

describe('UserRoleTable', () => {
    it('should render', () => {
        let domains = [];
        let roles = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let role1 = {
            name: 'a',
        };
        let role2 = {
            name: 'b',
        };
        roles.push(role1);
        roles.push(role2);
        const { getByTestId } = render(
            <UserRoleTable roles={roles} api={API()} domain={domains} />
        );
        const userroletable = getByTestId('userroletable');

        expect(userroletable).toMatchSnapshot();
    });
});

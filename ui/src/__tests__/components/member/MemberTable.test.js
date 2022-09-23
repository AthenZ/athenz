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
import MemberTable from '../../../components/member/MemberTable';
import API from '../../../api';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('MemberTable', () => {
    it('should render member table', () => {
        let members = [];
        let domain = 'domain';
        let role = 'roleName';
        let user1 = {
            memberName: 'user1',
            approved: true,
        };
        let user2 = {
            memberName: 'user2',
            approved: false,
        };
        let user3 = {
            memberName: 'user3',
            approved: false,
        };
        let user4 = {
            memberName: 'user4',
            approved: true,
        };
        members.push(user1);
        members.push(user2);
        members.push(user3);
        members.push(user4);

        const { getByTestId } = renderWithRedux(
            <MemberTable
                domain={domain}
                role={role}
                members={members}
                caption='Approved'
                justificationRequired={true}
            />
        );
        const membertable = getByTestId('member-table');

        expect(membertable).toMatchSnapshot();
    });
});

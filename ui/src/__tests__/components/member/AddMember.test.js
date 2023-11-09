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
import { fireEvent, screen, waitFor } from '@testing-library/react';
import AddMember from '../../../components/member/AddMember';
import {
    getStateWithUserList,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import { USER_DOMAIN } from '../../../components/constants/constants';
import { act } from 'react-dom/test-utils';

describe('AddMember', () => {
    it('should render', () => {
        let domain = 'domain';
        let role = 'roleName';
        const onCancelMock = jest.fn();
        const { getByTestId } = renderWithRedux(
            <AddMember
                domain={domain}
                role={role}
                justificationRequired={true}
                onCancel={onCancelMock}
            />
        );
        const roleMemberForm = getByTestId('add-member');
        expect(roleMemberForm).toMatchSnapshot();
    });

    it('search member', async () => {
        let domain = 'domain';
        let role = 'roleName';
        let userList = { userList: [{ login: 'mock', name: 'Mock User' }] };
        const onCancelMock = jest.fn();
        renderWithRedux(
            <AddMember
                domain={domain}
                role={role}
                justificationRequired={true}
                onCancel={onCancelMock}
                showAddMember={true}
            />,
            getStateWithUserList(userList)
        );

        // change input to mocked user
        await act(async () => {
            fireEvent.change(
                screen.getByPlaceholderText(
                    `${USER_DOMAIN}.<shortid> or <domain>.<service> or unix.<group>`
                ),
                {
                    target: { value: 'mock' },
                }
            );
        });

        // verify the correct input 'Mock User [user.mock]' is presented
        await waitFor(() =>
            expect(
                screen.getByText('Mock User [user.mock]')
            ).toBeInTheDocument()
        );
    });
});

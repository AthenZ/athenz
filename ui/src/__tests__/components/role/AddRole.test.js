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
import AddRole from '../../../components/role/AddRole';
import {
    buildDomainDataForState,
    getStateWithDomainData,
    getStateWithUserList,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import AddMember from '../../../components/member/AddMember';
import { act } from 'react-dom/test-utils';
import {
    ADD_ROLE_MEMBER_PLACEHOLDER,
    USER_DOMAIN,
} from '../../../components/constants/constants';

describe('AddRole', () => {
    it('should render', () => {
        let domain = 'domain';
        const onCancelMock = jest.fn();

        const { getByTestId } = renderWithRedux(
            <AddRole
                domain={domain}
                showAddRole={true}
                onCancel={onCancelMock}
            />
        );
        const addRoleForm = getByTestId('add-role');
        expect(addRoleForm).toMatchSnapshot();
    });
    it('should open add model without justification input', async () => {
        let domain = 'domain';
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            auditEnabled: false,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onCancelMock = jest.fn();

        const { getByTestId } = renderWithRedux(
            <AddRole
                domain={domain}
                showAddRole={true}
                onCancel={onCancelMock}
            />,
            getStateWithDomainData(domainData)
        );
        await waitFor(() =>
            expect(getByTestId('add-modal-message')).toBeInTheDocument()
        );

        const addRoleForm = getByTestId('add-modal-message');
        expect(addRoleForm).toMatchSnapshot();
    });
    it('should open add model with justification input', async () => {
        let domain = 'domain';
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        const onCancelMock = jest.fn();

        const { getByTestId } = renderWithRedux(
            <AddRole
                domain={domain}
                showAddRole={true}
                onCancel={onCancelMock}
            />,
            getStateWithDomainData(domainData)
        );
        await waitFor(() =>
            expect(getByTestId('add-modal-message')).toBeInTheDocument()
        );

        const addRoleForm = getByTestId('add-modal-message');
        expect(addRoleForm).toMatchSnapshot();
    });

    it('search member add role', async () => {
        let domain = 'domain';
        let userList = { userList: [{ login: 'mock', name: 'Mock User' }] };
        const onCancelMock = jest.fn();
        renderWithRedux(
            <AddRole
                domain={domain}
                showAddRole={true}
                onCancel={onCancelMock}
            />,
            getStateWithUserList(userList)
        );

        // change input to mocked user
        await act(async () => {
            fireEvent.change(
                screen.getByPlaceholderText(ADD_ROLE_MEMBER_PLACEHOLDER),
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

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
import { waitFor } from '@testing-library/react';
import MemberPage from '../../../../../../pages/domain/[domain]/role/[role]/members';
import {
    mockAllDomainDataApiCalls,
    mockRolesApiCalls,
    renderWithRedux,
} from '../../../../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../../../../mock/MockApi';

describe('MemberPage', () => {
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let query = {
            domain: 'dom',
        };
        let domainDetails = {
            modified: '2020-02-12T21:44:37.792Z',
        };
        let rolesDetails = [
            {
                roleName: 'redux-role1',
                modified: '2020-02-12T21:44:37.792Z',
                roleMembers: [],
            },
        ];
        let roleDetails = {
            roleName: 'redux-role1',
            modified: '2020-02-12T21:44:37.792Z',
            roleMembers: [],
        };
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
            userData: {
                userLink: {
                    title: 'User Link',
                    url: '',
                    target: '_blank',
                },
            },
        };
        const mockApi = {
            ...mockAllDomainDataApiCalls(),
            ...mockRolesApiCalls(),
            listUserDomains: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(domains);
                })
            ),
            getDomain: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(domainDetails);
                })
            ),
            getHeaderDetails: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(headerDetails);
                })
            ),
            getRoles: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(rolesDetails);
                })
            ),
            getRole: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(roleDetails);
                })
            ),
            getRoleMembers: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([
                        {
                            members: [],
                        },
                    ]);
                })
            ),
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([]);
                })
            ),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        };

        MockApi.setMockApi(mockApi);

        const { getByTestId } = renderWithRedux(
            <MemberPage
                reload={false}
                domainName='dom'
                roleName={'redux-role1'}
            />
        );
        await waitFor(() => {
            expect(getByTestId('member')).toBeInTheDocument();
        });
        const memberPage = getByTestId('member');
        expect(memberPage).toMatchSnapshot();
    });
});

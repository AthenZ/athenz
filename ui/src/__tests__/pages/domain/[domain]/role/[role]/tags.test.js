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
import { render, waitFor } from '@testing-library/react';
import RoleTagsPage from '../../../../../../pages/domain/[domain]/role/[role]/tags';
import MockApi from '../../../../../../mock/MockApi';
import {
    mockAllDomainDataApiCalls,
    mockRolesApiCalls,
    renderWithRedux,
} from '../../../../../../tests_utils/ComponentsTestUtils';
import {
    configStoreRoles,
    singleStoreRole,
} from '../../../../../redux/config/role.test';

describe('Roles Tag Page', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', async () => {
        const query = {
            domain: 'dom',
        };
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const userId = 'test';
        const domain = 'home.test';
        const domainDetails = {
            description: 'test',
            org: 'athenz',
            enabled: true,
            auditEnabled: false,
            account: '1231243134',
            ypmId: 0,
            name: 'home.test',
            modified: '2020-01-24T18:14:51.939Z',
            id: 'a48cb050-e4fa-11e7-9d38-9d13efb959d1',
        };
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
        };
        let roleDetails = {
            roleName: 'role1',
            modified: '2020-02-12T21:44:37.792Z',
            tags: {
                'tag-name': {
                    list: ['first', 'second'],
                },
            },
        };
        const mockApi = {
            ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
            ...mockRolesApiCalls(),
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([]);
                })
            ),
            getRole: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleStoreRole)),
            getRoles: jest
                .fn()
                .mockReturnValue(Promise.resolve(configStoreRoles)),
            getRoleMembers: jest.fn().mockReturnValue(Promise.resolve([])),
            listUserDomains: jest
                .fn()
                .mockReturnValue(Promise.resolve(domains)),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        };
        MockApi.setMockApi(mockApi);

        const { getByTestId } = renderWithRedux(
            <RoleTagsPage
                req='req'
                userId={userId}
                query={query}
                reload={false}
                domainName={'dom'}
                roleName='singlerole'
            />,
            {
                roles: {
                    roles: {
                        'dom:role.singlerole': {
                            tags: { tag: { list: ['tag1'] } },
                        },
                    },
                },
            }
        );
        await waitFor(() =>
            expect(getByTestId('tag-list')).toBeInTheDocument()
        );
        const roleTagsPage = getByTestId('role-tags');
        expect(roleTagsPage).toMatchSnapshot();
    });
});

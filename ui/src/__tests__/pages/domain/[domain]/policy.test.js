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
import PolicyPage from '../../../../pages/domain/[domain]/policy';
import {
    mockAllDomainDataApiCalls,
    mockRolesApiCalls,
    renderWithRedux,
} from '../../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../../mock/MockApi';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('PolicyPage', () => {
    beforeEach(() => {
        MockApi.setMockApi({
            getPendingDomainMembersList: jest.fn().mockReturnValue([]),
        });
    });
    afterEach(() => MockApi.cleanMockApi());
    it('should render', async () => {
        const query = {
            domain: 'dom',
        };
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const userId = 'pgote';
        const domain = 'home.pgote';
        const domainDetails = {
            description: 'test',
            org: 'athenz',
            enabled: true,
            auditEnabled: false,
            account: '1231243134',
            ypmId: 0,
            name: 'home.pgote',
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

        const mockApi = {
            ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
            ...mockRolesApiCalls(),
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([]);
                })
            ),
            listUserDomains: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(domains);
                })
            ),
            getPolicies: jest.fn().mockReturnValue(
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
            <PolicyPage
                req='req'
                userId={userId}
                query={query}
                reload={false}
                domainName={domain}
                checked={false}
            />
        );
        await waitFor(() => {
            expect(getByTestId('policy')).toMatchSnapshot();
        });
    });
});

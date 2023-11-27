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
import ManageDomainsPage from '../../../pages/domain/manage';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import { getByText, waitFor } from '@testing-library/react';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('PageManageDomains', () => {
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const userId = 'pgote';
        const manageDomains = [
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    account: '111111',
                    ypmId: 0,
                    name: 'home.mujibur',
                    modified: '2018-01-31T19:43:14.476Z',
                    id: '77c25150-4f6a-11e6-a22d-0723ac92bd3d',
                },
            },
            {
                domain: {
                    description: 'test',
                    org: 'test',
                    enabled: true,
                    auditEnabled: false,
                    account: '14913436251',
                    ypmId: 0,
                    name: 'home.pgote',
                    modified: '2018-02-15T00:48:43.397Z',
                    id: '5fe71bb0-7642-11e7-8b74-f1fb574cabde',
                },
            },
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    ypmId: 0,
                    gcpProject: 'random-test-home',
                    gcpProjectNumber: '1243',
                    businessService: 'yca.US',
                    name: 'home.craman.testingui',
                    modified: '2023-10-26T16:05:31.507Z',
                },
            },

            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    ypmId: 0,
                    gcpProject: 'test-home',
                    gcpProjectNumber: '12432',
                    name: 'home.rkanchanapalli',
                    modified: '2023-10-12T18:15:04.348Z',
                },
            },
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    ypmId: 0,
                    name: 'home.rkanchanapalli.test1',
                    modified: '2023-10-18T16:20:21.738Z',
                },
            },
        ];

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
            listUserDomains: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(domains);
                })
            ),
            getMeta: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([]);
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
            <ManageDomainsPage
                req='req'
                userId={userId}
                reload={false}
                manageDomains={manageDomains}
                domain='dom'
                domainResult={[]}
                headerDetails={headerDetails}
            />
        );
        await waitFor(() =>
            expect(getByTestId('page-manage-domains')).toBeInTheDocument()
        );
        const pageManageDomains = getByTestId('page-manage-domains');
        expect(pageManageDomains).toMatchSnapshot();
    });
});

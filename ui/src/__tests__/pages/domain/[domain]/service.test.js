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
import ServicePage from '../../../../pages/domain/[domain]/service';
import MockApi from '../../../../mock/MockApi';
import {
    mockAllDomainDataApiCalls,
    renderWithRedux,
} from '../../../../tests_utils/ComponentsTestUtils';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('ServicePage', () => {
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
        const services = [
            {
                name: 'home.pgote.bastion',
                modified: '2017-12-21T18:59:09.372Z',
            },
            {
                name: 'home.pgote.openhouse',
                modified: '2017-12-19T20:24:41.195Z',
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
            ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
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
            getServices: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(services);
                })
            ),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        };
        MockApi.setMockApi(mockApi);

        const { getByTestId } = renderWithRedux(
            <ServicePage
                req='req'
                userId={userId}
                query={query}
                reload={false}
                domainName={domain}
            />
        );

        await waitFor(() => {
            expect(getByTestId('service')).toBeInTheDocument();
        });

        const servicePage = getByTestId('service');
        expect(servicePage).toMatchSnapshot();
    });
});

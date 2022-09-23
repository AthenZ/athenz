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
import DomainSettingsPage from '../../../../pages/domain/[domain]/domain-settings';
import {
    mockAllDomainDataApiCalls,
    renderWithRedux,
} from '../../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../../mock/MockApi';
import { waitFor } from '@testing-library/react';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('DomainSettingsPage', () => {
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
        };
        MockApi.setMockApi(mockApi);

        const { getByTestId } = renderWithRedux(
            <DomainSettingsPage
                req='req'
                userId='userid'
                query={query}
                reload={false}
                domainName='dom'
            />
        );

        await waitFor(() => {
            expect(getByTestId('domain-settings')).toBeInTheDocument();
        });

        const domainSettingsPage = getByTestId('domain-settings');
        expect(domainSettingsPage).toMatchSnapshot();
    });
});

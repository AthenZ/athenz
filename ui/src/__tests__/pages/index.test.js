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
import Home from '../../pages';
import { renderWithRedux } from '../../tests_utils/ComponentsTestUtils';
import MockApi from '../../mock/MockApi';
import { waitFor } from '@testing-library/react';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('Home', () => {
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'dom1' });
        domains.push({ name: 'dom2' });
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
        };
        MockApi.setMockApi({
            getPendingDomainMembersList: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
            getHeaderDetails: jest
                .fn()
                .mockReturnValue(Promise.resolve(headerDetails)),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        });

        const { getByTestId } = renderWithRedux(
            <Home domains={domains} userId='test' />,
            { domains: { domainsList: domains } }
        );
        await waitFor(() => expect(getByTestId('home')).toMatchSnapshot());
    });

    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'dom1' });
        domains.push({ name: 'dom2' });
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
        };
        MockApi.setMockApi({
            getPendingDomainMembersList: jest
                .fn()
                .mockRejectedValue(new Error('Error fetching pending members')),
            getHeaderDetails: jest
                .fn()
                .mockRejectedValue(new Error('Error fetching header details')),
            getReviewGroups: jest
                .fn()
                .mockImplementation(() => new Error('Error fetching groups')),
            getReviewRoles: jest
                .fn()
                .mockImplementation(() => new Error('Error fetching roles')),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
            getHeaderDetails: jest
                .fn()
                .mockImplementation(
                    () => new Error('Error fetching header details')
                ),
        });

        const { getByTestId } = renderWithRedux(
            <Home domains={domains} userId='test' />,
            { domains: { domainsList: domains } }
        );
        await waitFor(() => expect(getByTestId('home')).toMatchSnapshot());
    });
});

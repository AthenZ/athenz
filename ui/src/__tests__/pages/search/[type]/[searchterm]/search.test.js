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
import Search from '../../../../../pages/search/[type]/[searchterm]';
import { renderWithRedux } from '../../../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../../../mock/MockApi';
import { allDomainList, userDomainList } from '../../../../config/config.test';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('Search', () => {
    beforeEach(() => {
        MockApi.setMockApi({
            getPendingDomainMembersList: jest.fn().mockReturnValue([]),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        });
    });
    afterEach(() => MockApi.cleanMockApi());
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci', userDomain: true });

        const mockApi = {
            getPendingDomainMembersList: jest
                .fn()
                .mockReturnValue(Promise.resolve([])),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        };
        MockApi.setMockApi(mockApi);
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
        };

        const { getByTestId } = renderWithRedux(
            <Search
                domain='test'
                type='domain'
                userId={'pgote'}
                headerDetails={headerDetails}
                router={{ query: { searchterm: 'ci' } }}
            />,
            {
                domains: {
                    allDomainsList: [
                        {
                            name: 'test1',
                            adminDomain: true,
                        },
                        ...domains,
                    ],
                    domainsList: domains,
                    headerDetails: headerDetails,
                },
            }
        );
        await waitFor(() => expect(getByTestId('search')).toBeInTheDocument());
        const search = getByTestId('search');
        expect(search).toMatchSnapshot();
    });
});

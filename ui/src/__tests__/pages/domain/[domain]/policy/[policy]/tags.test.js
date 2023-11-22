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
import PolicyTagsPage from '../../../../../../pages/domain/[domain]/policy/[policy]/[version]/tags';
import MockApi from '../../../../../../mock/MockApi';
import {
    mockAllDomainDataApiCalls,
    mockPoliciesApiCalls,
    renderWithRedux,
} from '../../../../../../tests_utils/ComponentsTestUtils';
import {
    apiPolicies,
    singleStorePolicy,
} from '../../../../../redux/config/policy.test';
import { storeDomainData } from '../../../../../redux/config/domainData.test';

describe('Policies Tag Page', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const userId = 'test';
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
        const mockApi = {
            ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
            ...mockPoliciesApiCalls(),
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([]);
                })
            ),
            getPolicy: jest
                .fn()
                .mockReturnValue(Promise.resolve(singleStorePolicy)),
            getPolicies: jest
                .fn()
                .mockReturnValue(Promise.resolve(apiPolicies)),
            listUserDomains: jest
                .fn()
                .mockReturnValue(Promise.resolve(domains)),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        };
        MockApi.setMockApi(mockApi);

        const { getByTestId } = renderWithRedux(
            <PolicyTagsPage
                req='req'
                userId={userId}
                policyVersion={'2'}
                reload={false}
                domainName={'dom'}
                policyName='policy1'
            />
        );
        await waitFor(() =>
            expect(getByTestId('tag-list')).toBeInTheDocument()
        );
        const policyTagsPage = getByTestId('policy-tags');
        expect(policyTagsPage).toMatchSnapshot();
    });
});

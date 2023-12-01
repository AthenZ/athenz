/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import React from 'react';
import { waitFor } from '@testing-library/react';
import WorkflowRole from '../../../pages/workflow/role';
import MockApi from '../../../mock/MockApi';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import { mockAllDomainDataApiCalls } from '../../../tests_utils/ComponentsTestUtils';

describe('WorkflowRole', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should render without error', async () => {
        const mockApi = {
            ...mockAllDomainDataApiCalls(),
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve({});
                })
            ),
            getReviewRoles: jest.fn().mockReturnValue({
                list: [
                    {
                        domainName: 'home.jtsang01',
                        name: 'hellodemo',
                        memberExpiryDays: 5,
                        memberReviewDays: 5,
                        serviceExpiryDays: 0,
                        serviceReviewDays: 0,
                        groupExpiryDays: 5,
                        groupReviewDays: 5,
                        lastReviewedDate: '2023-11-20T19:07:54.229Z',
                    },
                    {
                        domainName: 'home.jtsang01',
                        name: 'r2',
                        memberExpiryDays: 5,
                        memberReviewDays: 5,
                        serviceExpiryDays: 5,
                        serviceReviewDays: 5,
                        groupExpiryDays: 5,
                        groupReviewDays: 5,
                    },
                    {
                        domainName: 'home.jtsang01',
                        name: 'r3',
                        memberExpiryDays: 5,
                        memberReviewDays: 5,
                        serviceExpiryDays: 5,
                        serviceReviewDays: 5,
                        groupExpiryDays: 5,
                        groupReviewDays: 5,
                    },
                    {
                        domainName: 'home.jtsang01',
                        name: 'r4',
                        memberExpiryDays: 5,
                        memberReviewDays: 5,
                        serviceExpiryDays: 5,
                        serviceReviewDays: 5,
                        groupExpiryDays: 5,
                        groupReviewDays: 5,
                    },
                    {
                        domainName: 'home.jtsang01',
                        name: 'r5',
                        memberExpiryDays: 5,
                        memberReviewDays: 5,
                        serviceExpiryDays: 5,
                        serviceReviewDays: 5,
                        groupExpiryDays: 5,
                        groupReviewDays: 5,
                    },
                    {
                        domainName: 'home.jtsang01',
                        name: 'rolereviewtest',
                        memberExpiryDays: 10,
                        memberReviewDays: 10,
                        serviceExpiryDays: 0,
                        serviceReviewDays: 0,
                        groupExpiryDays: 10,
                        groupReviewDays: 10,
                    },
                ],
            }),
        };
        MockApi.setMockApi(mockApi);
        const query = {
            domain: 'dom',
        };
        const domain = 'home.jtsang01';
        const { getByTestId } = renderWithRedux(
            <WorkflowRole
                req='req'
                userId={'user.jtsang01'}
                query={query}
                domain={domain}
            />
        );

        await waitFor(() =>
            expect(getByTestId('workflow-role-review')).toBeInTheDocument()
        );
        const pendingapproval = getByTestId('workflow-role-review');
        expect(pendingapproval).toMatchSnapshot();
    });
});

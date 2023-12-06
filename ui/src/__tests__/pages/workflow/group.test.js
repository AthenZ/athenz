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
import WorkflowGroup from '../../../pages/workflow/group';
import MockApi from '../../../mock/MockApi';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import { mockAllDomainDataApiCalls } from '../../../tests_utils/ComponentsTestUtils';

describe('WorkflowGroup', () => {
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
            getReviewGroups: jest.fn().mockReturnValue({
                list: [
                    {
                        domainName: 'home.jtsang01',
                        name: 'heyreviewthis',
                        memberExpiryDays: 10,
                        memberReviewDays: 0,
                        serviceExpiryDays: 10,
                        serviceReviewDays: 0,
                        groupExpiryDays: 0,
                        groupReviewDays: 0,
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
            <WorkflowGroup
                req='req'
                userId={'user.jtsang01'}
                query={query}
                domain={domain}
            />
        );

        await waitFor(() =>
            expect(getByTestId('workflow-group-review')).toBeInTheDocument()
        );
        const pendingapproval = getByTestId('workflow-group-review');
        expect(pendingapproval).toMatchSnapshot();
    });
});

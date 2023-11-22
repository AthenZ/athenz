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
import { render, waitFor } from '@testing-library/react';
import WorkflowAdmin from '../../../pages/workflow/admin';
import {
    mockAllDomainDataApiCalls,
    mockRolesApiCalls,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

describe('PendingApprovalPage', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', async () => {
        const query = {
            domain: 'dom',
        };
        const domains = [
            {
                name: 'home.jsun01',
                adminDomain: true,
                userDomain: true,
            },
        ];
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

        const pendingData = {
            'home.domain1user.test1testrole1': {
                category: 'role',
                domainName: 'home.domain1',
                memberName: 'user.test1',
                memberNameFull: 'Test',
                roleName: 'testrole1',
                userComment: 'testing1',
                auditRef: 'test',
                requestPrincipal: 'user.craman',
                requestPrincipalFull: 'Test',
                requestTime: '2022-02-15T18:14:12.999Z',
                expiryDate: null,
                auditRefMissing: false,
            },
            'home.domain2user.test2add-test': {
                category: 'role',
                domainName: 'home.domain2',
                memberName: 'user.test2',
                memberNameFull: 'Test',
                roleName: 'add-test',
                userComment: 'test',
                auditRef: 'test',
                requestPrincipal: 'user.craman',
                requestPrincipalFull: 'Test',
                requestTime: '2022-02-16T16:02:45.235Z',
                expiryDate: null,
                auditRefMissing: false,
            },
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
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(pendingData);
                })
            ),
            getReviewGroups: jest.fn().mockReturnValue([]),
            getReviewRoles: jest.fn().mockReturnValue([]),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
            listUserDomains: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve(domains);
                })
            ),
        };
        MockApi.setMockApi(mockApi);

        const { getByTestId } = renderWithRedux(
            <WorkflowAdmin
                req='req'
                userId={userId}
                query={query}
                domain={domain}
            />
        );

        await waitFor(() =>
            expect(getByTestId('pending-approval')).toBeInTheDocument()
        );
        const pendingapproval = getByTestId('pending-approval');
        expect(pendingapproval).toMatchSnapshot();
    });
});

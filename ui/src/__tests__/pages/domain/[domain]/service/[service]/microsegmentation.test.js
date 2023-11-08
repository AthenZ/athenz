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
import { screen, waitFor } from '@testing-library/react';
import MockApi from '../../../../../../mock/MockApi';
import {
    mockAllDomainDataApiCalls,
    mockRolesApiCalls,
    renderWithRedux,
} from '../../../../../../tests_utils/ComponentsTestUtils';
import ServiceMicrosegmentationPage from '../../../../../../pages/domain/[domain]/service/[service]/microsegmentation';
import {
    apiAssertionConditions,
    modified,
} from '../../../../../config/config.test';

describe('Service Microsegmentation Page', () => {
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

        let apiServices = [
            {
                name: 'dom.openhouse',
                modified: modified,
            },
            {
                name: 'dom.service2',
                modified: modified,
            },
        ];

        let policies = [
            {
                name: 'dom:policy.acl.openhouse.inbound',
                modified: modified,
                assertions: [
                    {
                        role: 'dom:role.acl.openhouse.inbound-test1',
                        resource: 'dom:openhouse',
                        action: 'TCP-IN:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 34567,
                        conditions: apiAssertionConditions,
                    },
                    {
                        role: 'dom:role.acl.openhouse.inbound-test2',
                        resource: 'dom:openhouse',
                        action: 'TCP-IN:1024-65535:8443-8444',
                        effect: 'ALLOW',
                        id: 34890,
                        conditions: apiAssertionConditions,
                    },
                ],
                version: '0',
                active: true,
            },
            {
                name: 'dom:policy.acl.openhouse.outbound',
                modified: modified,
                assertions: [
                    {
                        role: 'dom:role.acl.openhouse.outbound-test2',
                        resource: 'dom:openhouse',
                        action: 'TCP-OUT:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 76543,
                        conditions: apiAssertionConditions,
                    },
                ],
                version: '0',
                active: true,
            },
            {
                name: 'dom:policy.acl.service2.inbound',
                modified: modified,
                assertions: [
                    {
                        role: 'dom:role.acl.service2.inbound-test4',
                        resource: 'dom:service2',
                        action: 'TCP-IN:1024-65535:4443-4443',
                        effect: 'ALLOW',
                        id: 39890,
                        conditions: apiAssertionConditions,
                    },
                ],
                version: '0',
                active: true,
            },
        ];

        let roles = [
            {
                name: 'dom:role.acl.openhouse.inbound-test1',
                roleMembers: [
                    { memberName: 'user.test1' },
                    { memberName: 'user.test2' },
                ],
            },
            {
                name: 'dom:role.acl.openhouse.inbound-test2',
                roleMembers: [
                    { memberName: 'user.test3' },
                    { memberName: 'user.test4' },
                ],
            },
            {
                name: 'dom:role.acl.openhouse.outbound-test3',
                roleMembers: [
                    { memberName: 'user.test1' },
                    { memberName: 'user.test2' },
                ],
            },
            {
                name: 'dom:role.acl.service2.inbound-test4',
                roleMembers: [
                    { memberName: 'user.test1' },
                    { memberName: 'user.test2' },
                ],
            },
        ];

        const mockApi = {
            ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
            ...mockRolesApiCalls(),
            getPendingDomainMembersList: jest.fn().mockReturnValue(
                new Promise((resolve, reject) => {
                    resolve([]);
                })
            ),
            listUserDomains: jest
                .fn()
                .mockReturnValue(Promise.resolve(domains)),
            getPolicies: jest.fn().mockReturnValue(Promise.resolve(policies)),
            getServices: jest
                .fn()
                .mockReturnValue(Promise.resolve(apiServices)),
            getRoles: jest.fn().mockReturnValue(Promise.resolve(roles)),
        };
        MockApi.setMockApi(mockApi);

        const { getByTestId } = await renderWithRedux(
            <ServiceMicrosegmentationPage
                req='req'
                userId={userId}
                reload={false}
                domainName={'dom'}
                serviceName='openhouse'
            />
        );
        await waitFor(() =>
            expect(getByTestId('segmentation-data-list')).toBeInTheDocument()
        );

        await waitFor(() =>
            expect(screen.getByText('Inbound (2)')).toBeInTheDocument()
        );

        await waitFor(() =>
            expect(screen.getByText('Outbound (1)')).toBeInTheDocument()
        );

        const serviceMicrosegmentationPage = getByTestId(
            'service-microsegmentation'
        );
        expect(serviceMicrosegmentationPage).toMatchSnapshot();
    });
});

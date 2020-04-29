/*
 * Copyright 2020 Verizon Media
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
import { render } from '@testing-library/react';
import Workflow from '../../pages/workflow';
describe('PendingApprovalPage', () => {
    it('should render', () => {
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
            domainRoleMembersList: [
                {
                    domainName: 'home.jsun01',
                    members: [
                        {
                            memberName: 'user.pgote',
                            memberRoles: [
                                {
                                    roleName: 'self_serve',
                                    active: false,
                                },
                            ],
                        },
                    ],
                },
            ],
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

        const { getByTestId } = render(
            <Workflow
                domains={domains}
                req='req'
                userId={userId}
                query={query}
                domainDetails={domainDetails}
                domain={domain}
                headerDetails={headerDetails}
            />
        );

        const pendingapproval = getByTestId('pending-approval');
        expect(pendingapproval).toMatchSnapshot();
    });
});

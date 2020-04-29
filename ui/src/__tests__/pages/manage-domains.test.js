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
import ManageDomainsPage from '../../pages/manage-domains';

describe('PageManageDomains', () => {
    it('should render', () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const userId = 'pgote';
        const manageDomains = [
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    account: '111111',
                    ypmId: 0,
                    name: 'home.mujibur',
                    modified: '2018-01-31T19:43:14.476Z',
                    id: '77c25150-4f6a-11e6-a22d-0723ac92bd3d',
                },
            },
            {
                domain: {
                    description: 'test',
                    org: 'test',
                    enabled: true,
                    auditEnabled: false,
                    account: '14913436251',
                    ypmId: 0,
                    name: 'home.pgote',
                    modified: '2018-02-15T00:48:43.397Z',
                    id: '5fe71bb0-7642-11e7-8b74-f1fb574cabde',
                },
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

        const { getByTestId } = render(
            <ManageDomainsPage
                domains={domains}
                req='req'
                userId={userId}
                reload={false}
                manageDomains={manageDomains}
                domain='dom'
                domainResult={[]}
                headerDetails={headerDetails}
            />
        );
        const pageManageDomains = getByTestId('page-manage-domains');
        expect(pageManageDomains).toMatchSnapshot();
    });
});

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
import { render } from '@testing-library/react';
import StaticInstancePage from '../../pages/static-instance';

const testInstancedetails = {
    workLoadData: [
        {
            domainName: null,
            serviceName: null,
            uuid: '10.1.1.1',
            ipAddresses: [Array],
            hostname: null,
            provider: 'Static',
            updateTime: '2021-05-15T01:17:31.759Z',
            certExpiryTime: null,
        },
    ],
    workLoadMeta: {
        totalDynamic: 10,
        totalStatic: 9,
        totalRecords: 19,
        totalHealthyDynamic: 8,
    },
};

describe('StaticInstancePage', () => {
    it('should render', () => {
        let domains = [];
        let instanceDetails = testInstancedetails;
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let query = {
            domain: 'dom',
            service: 'serv',
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

        let serviceHeaderDetails = {
            description:
                'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
            url: '',
            target: '_blank',
        };

        const { getByTestId } = render(
            <StaticInstancePage
                domains={domains}
                req='req'
                userId='userid'
                query={query}
                reload={false}
                domainDetails={domainDetails}
                domain='dom'
                domainResult={[]}
                headerDetails={headerDetails}
                instanceDetails={instanceDetails}
                serviceHeaderDetails={serviceHeaderDetails}
            />
        );
        const staticInstancePage = getByTestId('static-instance');
        expect(staticInstancePage).toMatchSnapshot();
    });

    it('should render for categoryType', () => {
        let domains = [];
        let instanceDetails = testInstancedetails;
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let query = {
            domain: 'dom',
            service: 'serv',
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

        let serviceHeaderDetails = {
            description:
                'Here you can add / see instances which can not obtain Athenz identity because of limitations, but would be associated with your service.',
            url: '',
            target: '_blank',
        };

        const { getByTestId } = render(
            <StaticInstancePage
                domains={domains}
                req='req'
                userId='userid'
                query={query}
                reload={false}
                domainDetails={domainDetails}
                domain='dom'
                categoryType='Static'
                domainResult={[]}
                headerDetails={headerDetails}
                instanceDetails={instanceDetails}
                serviceHeaderDetails={serviceHeaderDetails}
            />
        );
        const staticInstancePage = getByTestId('static-instance');
        expect(staticInstancePage).toMatchSnapshot();
    });
});

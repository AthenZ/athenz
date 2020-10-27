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
import { render, fireEvent, waitForElement } from '@testing-library/react';
import ServiceRow from '../../../components/service/ServiceRow';

const allProviders = [
    {
        id: 'aws_instance_launch_provider',
        name: 'AWS EC2/EKS/Fargate launches instances for the service',
    },
];

describe('ServiceRow', () => {
    it('should render row', () => {
        const domainName = 'domain';
        const serviceName = 'serviceName';
        const modified = '2017-12-19T20:24:41.195Z';
        const api = {};
        const color = '';
        const newService = false;
        const { getByTestId } = render(
            <table>
                <tbody>
                    <ServiceRow
                        serviceName={serviceName}
                        domainName={domainName}
                        api={api}
                        color={color}
                        modified={modified}
                        newService={newService}
                    />
                </tbody>
            </table>
        );
        const serviceRow = getByTestId('service-row');
        expect(serviceRow).toMatchSnapshot();
    });

    it('should render keys on click of key', async () => {
        const domainName = 'domain';
        const serviceName = 'serviceName';
        const modified = '2017-12-19T20:24:41.195Z';
        let toReturn = {
            name: 'domain.service',
            description: 'This is a service',
            publicKeys: [
                {
                    key:
                        'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2…wQ1UKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                    id: '0',
                },
                {
                    key:
                        'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2…wQ1UKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                    id: '1',
                },
            ],
            modified: '2020-03-06T04:01:19.848Z',
        };

        const api = {
            getService: function(domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    resolve(toReturn);
                });
            },
        };
        const color = '';
        const newService = false;
        const { getByText, getByTitle } = render(
            <table>
                <tbody>
                    <ServiceRow
                        serviceName={serviceName}
                        domainName={domainName}
                        api={api}
                        color={color}
                        modified={modified}
                        newService={newService}
                    />
                </tbody>
            </table>
        );

        fireEvent.click(getByTitle('key'));

        expect(
            await waitForElement(() => getByText('Details'))
        ).toMatchSnapshot();

        expect(
            await waitForElement(() => getByText(toReturn.description))
        ).toMatchSnapshot();

        expect(
            await waitForElement(() =>
                getByText('Public Key Version: ' + toReturn.publicKeys[0].id)
            )
        ).toMatchSnapshot();

        expect(
            await waitForElement(() =>
                getByText('Public Key Version: ' + toReturn.publicKeys[1].id)
            )
        ).toMatchSnapshot();
    });

    it('should render providers on click of cloud', async () => {
        const domainName = 'domain';
        const serviceName = 'serviceName';
        const modified = '2017-12-19T20:24:41.195Z';
        let toReturn = {
            provider: {
                aws_instance_launch_provider: 'allow',
            },
            allProviders: allProviders,
        };
        const api = {
            getProvider: function(domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    resolve(toReturn);
                });
            },
        };
        const color = '';
        const newService = false;
        const { getByText, getByTitle } = render(
            <table>
                <tbody>
                    <ServiceRow
                        serviceName={serviceName}
                        domainName={domainName}
                        api={api}
                        color={color}
                        modified={modified}
                        newService={newService}
                    />
                </tbody>
            </table>
        );

        fireEvent.click(getByTitle('cloud'));

        expect(
            await waitForElement(() =>
                getByText(
                    'AWS EC2/EKS/Fargate launches instances for the service'
                )
            )
        ).toMatchSnapshot();
    });
});

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
import { render, fireEvent, waitFor } from '@testing-library/react';
import ServiceRow from '../../../components/service/ServiceRow';
import {
    buildServicesForState,
    getStateWithServices,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import { serviceDelimiter } from '../../../redux/config';

const allProviders = [
    {
        id: 'aws_instance_launch_provider',
        name: 'AWS EC2/EKS/Fargate launches instances for the service',
    },
];

const domainName = 'domain';
const serviceName = 'serviceName';
const fullServiceName = `${domainName}${serviceDelimiter}${serviceName.toLowerCase()}`;
describe('ServiceRow', () => {
    it('should render row', () => {
        const modified = '2017-12-19T20:24:41.195Z';
        const color = '';
        const newService = false;
        const timeZone = 'UTC';
        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <ServiceRow
                        serviceName={serviceName}
                        domainName={domainName}
                        color={color}
                        modified={modified}
                        newService={newService}
                        timeZone={timeZone}
                    />
                </tbody>
            </table>
        );
        const serviceRow = getByTestId('service-row');
        expect(serviceRow).toMatchSnapshot();
    });

    it('should render keys on click of key', async () => {
        const modified = '2017-12-19T20:24:41.195Z';
        let servicesForInitialState = buildServicesForState(
            {
                [fullServiceName]: {
                    name: fullServiceName,
                    description: 'This is a service',
                    publicKeys: {
                        0: {
                            key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2…wQ1UKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                            id: '0',
                        },
                        1: {
                            key: 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2…wQ1UKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t',
                            id: '1',
                        },
                    },
                    modified: '2020-03-06T04:01:19.848Z',
                },
            },
            domainName
        );

        const color = '';
        const newService = false;
        const timeZone = 'UTC';
        const { getByText, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <ServiceRow
                        serviceName={serviceName}
                        domainName={domainName}
                        color={color}
                        modified={modified}
                        newService={newService}
                        timeZone={timeZone}
                    />
                </tbody>
            </table>,
            getStateWithServices(servicesForInitialState)
        );

        fireEvent.click(getByTitle('key'));

        expect(await waitFor(() => getByText('Details'))).toMatchSnapshot();

        expect(
            await waitFor(() =>
                getByText(
                    servicesForInitialState.services[fullServiceName][
                        'description'
                    ]
                )
            )
        ).toMatchSnapshot();

        expect(
            await waitFor(() =>
                getByText(
                    'Public Key Version: ' +
                        servicesForInitialState.services[fullServiceName]
                            .publicKeys['0']['id']
                )
            )
        ).toMatchSnapshot();

        expect(
            await waitFor(() =>
                getByText(
                    'Public Key Version: ' +
                        servicesForInitialState.services[fullServiceName]
                            .publicKeys['1']['id']
                )
            )
        ).toMatchSnapshot();
    });
    it('should render providers on click of cloud', async () => {
        const modified = '2017-12-19T20:24:41.195Z';
        let toReturn = {
            provider: {
                aws_instance_launch_provider: 'allow',
            },
            allProviders: allProviders,
        };
        const api = {
            getServices: jest
                .fn()
                .mockReturnValue(Promise.resolve([{ name: fullServiceName }])),
            getProvider: jest.fn().mockReturnValue(Promise.resolve(toReturn)),
        };
        MockApi.setMockApi(api);
        const color = '';
        const newService = false;
        const timeZone = 'UTC';
        const { getByText, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <ServiceRow
                        serviceName={serviceName}
                        domainName={domainName}
                        api={api}
                        color={color}
                        modified={modified}
                        newService={newService}
                        timeZone={timeZone}
                    />
                </tbody>
            </table>,
            getStateWithServices(buildServicesForState({}))
        );

        fireEvent.click(getByTitle('cloud'));

        expect(
            await waitFor(() =>
                getByText(
                    'AWS EC2/EKS/Fargate launches instances for the service'
                )
            )
        ).toMatchSnapshot();
    });
});

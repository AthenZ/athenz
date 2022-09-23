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
import {
    render,
    fireEvent,
    waitForElement,
    waitFor,
} from '@testing-library/react';
import ProviderTable from '../../../components/service/ProviderTable';
import {
    buildServicesForState,
    getStateWithServices,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import { getExpiryTime } from '../../../redux/utils';

const allProviders = [
    {
        id: 'aws_instance_launch_provider',
        name: 'AWS EC2/EKS/Fargate launches instances for the service',
    },
];

const domain = 'domain';
const service = 'service';
const fullServiceName = domain + '.' + service;

describe('ProviderTable', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', () => {
        const provider = {
            aws_instance_launch_provider: 'allow',
        };
        const color = '';
        const services = {
            [fullServiceName]: {
                name: service,
                provider: provider,
            },
        };
        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(
                buildServicesForState(services, domain, allProviders)
            )
        );
        const providerTable = getByTestId('provider-table');
        expect(providerTable).toMatchSnapshot();
    });

    it('should render error if allow api throws error', async () => {
        const provider = {
            expiry: getExpiryTime(),
            aws_instance_launch_provider: 'not',
        };
        const color = '';
        const services = {
            [fullServiceName]: {
                name: service,
                provider: provider,
            },
        };
        const api = {
            allowProviderTemplate: function (
                domainName,
                serviceName,
                provider,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
        };

        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(
                buildServicesForState(services, domain, allProviders)
            )
        );
        fireEvent.click(getByText('Allow'));
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render again if allow provider succeeds', async () => {
        const provider = {
            expiry: getExpiryTime(),
            aws_instance_launch_provider: 'not',
        };
        const color = '';
        const services = {
            [fullServiceName]: {
                name: service,
                provider: provider,
            },
        };
        const api = {
            allowProviderTemplate: function (
                domainName,
                serviceName,
                provider,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(
                buildServicesForState(services, domain, allProviders)
            )
        );
        fireEvent.click(getByText('Allow'));
        expect(await waitFor(() => getByTitle('checkmark'))).toMatchSnapshot();
    });
});

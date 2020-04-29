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
import ProviderTable from '../../../components/service/ProviderTable';

const allProviders = [
    {
        id: 'aws_instance_launch_provider',
        name: 'AWS EC2/EKS/Fargate launches instances for the service',
    },
];

describe('ProviderTable', () => {
    it('should render', () => {
        const domain = 'domain';
        const service = 'service';
        const provider = {
            provider: {
                aws_instance_launch_provider: 'allow',
            },
        };
        const color = '';
        const api = {};

        const { getByTestId } = render(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            api={api}
                            service={service}
                            provider={provider}
                            color={color}
                            allProviders={allProviders}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const providerTable = getByTestId('provider-table');
        expect(providerTable).toMatchSnapshot();
    });

    it('should render error if allow api throws error', async () => {
        const domain = 'domain';
        const service = 'service';
        const provider = {
            provider: {
                aws_instance_launch_provider: 'not',
            },
        };
        const color = '';
        const api = {
            allowProviderTemplate: function(
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

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            api={api}
                            service={service}
                            provider={provider}
                            color={color}
                            allProviders={allProviders}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByText('Allow'));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error if there is error in providers', async () => {
        const domain = 'domain';
        const service = 'service';
        const provider = {
            provider: {
                aws_lambda_instance_launch_provider: 'not',
            },
            errorMessage: 'test-error',
        };
        const color = '';
        const api = {
            allowProviderTemplate: function(
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

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            api={api}
                            service={service}
                            provider={provider}
                            color={color}
                            allProviders={allProviders}
                        />
                    </tr>
                </tbody>
            </table>
        );
        expect(getByTestId('error-message')).toMatchSnapshot();
    });

    it('should render again if allow provider succeeds', async () => {
        const domain = 'domain';
        const service = 'service';
        const provider = {
            provider: {
                aws_instance_launch_provider: 'not',
            },
        };
        const color = '';
        const api = {
            allowProviderTemplate: function(
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

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <ProviderTable
                            domain={domain}
                            api={api}
                            service={service}
                            provider={provider}
                            color={color}
                            allProviders={allProviders}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByText('Allow'));
        expect(
            await waitForElement(() => getByTitle('checkmark'))
        ).toMatchSnapshot();
    });
});

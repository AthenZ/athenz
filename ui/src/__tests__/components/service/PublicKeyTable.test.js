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
import { fireEvent, waitFor } from '@testing-library/react';
import PublicKeyTable from '../../../components/service/PublicKeyTable';
import {
    buildServicesForState,
    getStateWithServices,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import { getExpiredTime } from '../../../redux/utils';

const domain = 'domain';
const service = 'service';
const serviceFullName = `${domain}.${service}`;

describe('PublicKeyTable', () => {
    it('should render', () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: 'home.pgote.openhouse',
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                },
            },
            domain
        );
        const color = '';

        const { getByTestId } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(services)
        );
        const publicKeyTable = getByTestId('public-key-table');
        expect(publicKeyTable).toMatchSnapshot();
    });

    it('should render addKey after click addKey', async () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: 'home.pgote.openhouse',
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                },
            },
            domain
        );
        const color = '';

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(services)
        );
        fireEvent.click(getByText('Add Key'));

        expect(await waitFor(() => getByTestId('add-key'))).toMatchSnapshot();
    });

    it('should render deleteKey after click trash icon', async () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: 'home.pgote.openhouse',
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                    publicKeys: {
                        'test-id': {
                            id: 'test-id',
                            key: 'test-value',
                        },
                    },
                },
            },
            domain
        );
        const color = '';

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(services)
        );
        fireEvent.click(getByTitle('trash'));

        expect(
            await waitFor(() => getByText('This deletion is permanent'))
        ).toMatchSnapshot();
    });

    it('should not render deleteKeyModal after cancel', async () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: 'home.pgote.openhouse',
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                    publicKeys: {
                        'test-id': {
                            id: 'test-id',
                            key: 'test-value',
                        },
                    },
                },
            },
            domain
        );
        const color = '';

        const { getByText, getByTestId, getByTitle, queryByText } =
            renderWithRedux(
                <table>
                    <tbody>
                        <tr>
                            <PublicKeyTable
                                domain={domain}
                                service={service}
                                color={color}
                            />
                        </tr>
                    </tbody>
                </table>,
                getStateWithServices(services)
            );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitFor(() => getByTestId('delete-modal-cancel'))
        );
        expect(queryByText('This deletion is permanent')).toBeNull();
    });

    it('should render error if there is an error in submitDeleteKey(refresh)', async () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: 'home.pgote.openhouse',
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                    publicKeys: {
                        'test-id': {
                            id: 'test-id',
                            key: 'test-value',
                        },
                    },
                },
            },
            domain
        );
        const color = '';
        const api = {
            deleteKey: function (domainName, serviceName, keyId, _csrf) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(services)
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitFor(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error if there is an error in submitDeleteKey(other)', async () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: 'home.pgote.openhouse',
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                    publicKeys: {
                        'test-id': {
                            id: 'test-id',
                            key: 'test-value',
                        },
                    },
                },
            },
            domain
        );
        const color = '';
        const api = {
            deleteKey: function (domainName, serviceName, keyId, _csrf) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 1,
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
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(services)
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitFor(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should reloadService after successful delete', async () => {
        const services = buildServicesForState(
            {
                [serviceFullName]: {
                    name: serviceFullName,
                    description: 'delete-succeed',
                    modified: '2017-12-19T20:24:41.195Z',
                    publicKeys: {
                        'test-id': {
                            id: 'test-id',
                            key: 'test-value',
                        },
                    },
                },
            },
            domain
        );
        const color = '';
        const api = {
            deleteKey: function (domainName, serviceName, keyId, _csrf) {
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
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(services)
        );
        await waitFor(() => fireEvent.click(getByTitle('trash')));
        await waitFor(() =>
            expect(getByTestId('delete-modal-delete')).toBeInTheDocument()
        );
        await waitFor(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );
        await waitFor(() =>
            expect(getByTestId('public-key-table')).toBeInTheDocument()
        );
        expect(getByTestId('public-key-table')).toMatchSnapshot();
    });

    it('should render error if getService throws error', async () => {
        const serviceDetails = buildServicesForState(
            {
                [serviceFullName]: {
                    name: serviceFullName,
                    description: 'This is a default service for Openhouse.',
                    modified: '2017-12-19T20:24:41.195Z',
                    publicKeys: {
                        'test-id': {
                            id: 'test-id',
                            key: 'test-value',
                        },
                    },
                },
            },
            domain
        );
        serviceDetails.expiry = getExpiredTime();
        const color = '';
        const api = {
            deleteKey: function (domainName, serviceName, keyId, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
            getServices: function (domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    let err = {
                        statusCode: 404,
                        body: {
                            message: 'not found',
                        },
                    };
                    reject(err);
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            service={service}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>,
            getStateWithServices(serviceDetails)
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitFor(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });
});

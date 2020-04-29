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
import PublicKeyTable from '../../../components/service/PublicKeyTable';

describe('PublicKeyTable', () => {
    it('should render', () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
        };
        const color = '';
        const api = {};

        const { getByTestId } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        const publicKeyTable = getByTestId('public-key-table');
        expect(publicKeyTable).toMatchSnapshot();
    });

    it('should render addKey after click addKey', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
        };
        const color = '';
        const api = {};

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByText('Add Key'));

        expect(
            await waitForElement(() => getByTestId('add-key'))
        ).toMatchSnapshot();
    });

    it('should render deleteKey after click trash icon', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
        };
        const color = '';
        const api = {};

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByTitle('trash'));

        expect(
            await waitForElement(() => getByText('This deletion is permanent'))
        ).toMatchSnapshot();
    });

    it('should not render deleteKeyModal after cancel', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
        };
        const color = '';
        const api = {};

        const { getByText, getByTestId, getByTitle, queryByText } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitForElement(() => getByTestId('delete-modal-cancel'))
        );
        expect(queryByText('This deletion is permanent')).toBeNull();
    });

    it('should render error if there is an error in props', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.test.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
            errorMessage: 'err',
        };
        const color = '';
        const api = {};

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );

        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error if there is an error in submitDeleteKey(refresh)', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
        };
        const color = '';
        const api = {
            deleteKey: function(domainName, serviceName, keyId, _csrf) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitForElement(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error if there is an error in submitDeleteKey(other)', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
        };
        const color = '';
        const api = {
            deleteKey: function(domainName, serviceName, keyId, _csrf) {
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

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitForElement(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should reloadService after successful delete', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
        };
        const color = '';
        const api = {
            deleteKey: function(domainName, serviceName, keyId, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
            getService: function(domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    resolve({
                        description: 'delete-succeed',
                        publicKeys: [],
                    });
                });
            },
        };

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitForElement(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitForElement(() => getByTestId('public-key-table'))
        ).toMatchSnapshot();
    });

    it('should render error if getService throws error', async () => {
        const domain = 'domain';
        const service = 'service';
        const serviceDetails = {
            name: 'home.pgote.openhouse',
            description: 'This is a default service for Openhouse.',
            modified: '2017-12-19T20:24:41.195Z',
            publicKeys: [
                {
                    id: 'test-id',
                    key: 'test-value',
                },
            ],
        };
        const color = '';
        const api = {
            deleteKey: function(domainName, serviceName, keyId, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
            getService: function(domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    let err = {
                        statusCode: 404,
                        body: {
                            message: 'not found',
                        }
                    }
                    reject(err);
                });
            },
        };

        const { getByText, getByTestId, getByTitle } = render(
            <table>
                <tbody>
                    <tr>
                        <PublicKeyTable
                            domain={domain}
                            api={api}
                            service={service}
                            serviceDetails={serviceDetails}
                            color={color}
                        />
                    </tr>
                </tbody>
            </table>
        );
        fireEvent.click(getByTitle('trash'));
        fireEvent.click(
            await waitForElement(() => getByTestId('delete-modal-delete'))
        );
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });
});

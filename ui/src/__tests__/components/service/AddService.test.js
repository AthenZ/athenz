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

import AddService from '../../../components/service/AddService';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
const pageConfig = {
    servicePageConfig: {
        keyCreationLink: {
            title: 'Key Creation',
            url: 'https://test.com',
            target: '_blank',
        },
        keyCreationMessage: 'Test Message',
    },
};
describe('AddService', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', () => {
        const cancel = function () {};
        const domain = 'domain';
        const { getByTestId } = renderWithRedux(
            <AddService
                onCancel={cancel}
                domain={domain}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        const addService = getByTestId('add-service-form');
        expect(addService).toMatchSnapshot();
    });

    it('should render error after addService throws error(refresh)', async () => {
        const cancel = function () {};
        const domain = 'domain';
        const api = {
            addService: function (
                domainName,
                serviceName,
                description,
                endpoint,
                keyId,
                keyValue,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(api);

        const { getByTestId, querySelector, getByText, getAllByTestId } =
            renderWithRedux(
                <AddService
                    onCancel={cancel}
                    domain={domain}
                    showAddService={true}
                    pageConfig={pageConfig}
                />
            );
        const addServiceInput = await waitFor(() =>
            getAllByTestId('input-node')
        );
        fireEvent.change(addServiceInput[0], {
            target: {
                value: 'test-name',
            },
        });
        fireEvent.change(addServiceInput[1], {
            target: {
                value: 'test-key',
            },
        });
        fireEvent.click(await waitFor(() => getByText('Submit')));
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error after addService throws error(other)', async () => {
        const cancel = function () {};
        const domain = 'domain';
        const api = {
            addService: function (
                domainName,
                serviceName,
                description,
                endpoint,
                keyId,
                keyValue,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 1,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
        };
        MockApi.setMockApi(api);

        const { getByTestId, querySelector, getByText, getAllByTestId } =
            renderWithRedux(
                <AddService
                    onCancel={cancel}
                    domain={domain}
                    showAddService={true}
                    pageConfig={pageConfig}
                />
            );
        const addServiceInput = await waitFor(() =>
            getAllByTestId('input-node')
        );
        fireEvent.change(addServiceInput[0], {
            target: {
                value: 'test-name',
            },
        });
        fireEvent.change(addServiceInput[1], {
            target: {
                value: 'test-key',
            },
        });
        fireEvent.click(await waitFor(() => getByText('Submit')));
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should call onSubmit if add succeeds', async () => {
        const cancel = function () {};
        const domain = 'domain';
        let test = 0;
        const onSubmit = function (succedMessage) {
            test = test + 1;
        };
        const api = {
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
            addService: jest
                .fn()
                .mockReturnValue(Promise.resolve({ name: 'test-name' })),
        };
        MockApi.setMockApi(api);

        const { getByTestId, querySelector, getByText, getAllByTestId } =
            renderWithRedux(
                <AddService
                    onCancel={cancel}
                    domain={domain}
                    showAddService={true}
                    onSubmit={onSubmit}
                    pageConfig={pageConfig}
                />
            );
        const addServiceInput = await waitFor(() =>
            getAllByTestId('input-node')
        );
        fireEvent.change(addServiceInput[0], {
            target: {
                value: 'test-name',
            },
        });
        fireEvent.change(addServiceInput[1], {
            target: {
                value: 'test-key',
            },
        });
        fireEvent.click(await waitFor(() => getByText('Submit')));
        await waitFor(() => expect(test).toEqual(1));
    });

    it('should render error if no key name specified', async () => {
        const cancel = function () {};
        const domain = 'domain';
        const api = {
            getServices: jest.fn().mockReturnValue(Promise.resolve([])),
            addService: jest.fn().mockReturnValue(Promise.resolve()),
        };
        MockApi.setMockApi(api);
        const { getByTestId, querySelector, getByText, getAllByTestId } =
            renderWithRedux(
                <AddService
                    onCancel={cancel}
                    domain={domain}
                    showAddService={true}
                    pageConfig={pageConfig}
                />
            );
        fireEvent.click(await waitFor(() => getByText('Submit')));
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error when service already exists', async () => {
        const cancel = function () {};
        const domain = 'domain';
        // const service = 'test';
        const api = {
            getServices: jest
                .fn()
                .mockReturnValue(
                    Promise.resolve([{ name: domain + '.' + 'test-name' }])
                ),
            addService: function (
                domainName,
                serviceName,
                description,
                endpoint,
                keyId,
                keyValue,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 1,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
            getService: function (domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
        };
        MockApi.setMockApi(api);
        const { getByTestId, querySelector, getByText, getAllByTestId } =
            renderWithRedux(
                <AddService
                    onCancel={cancel}
                    domain={domain}
                    showAddService={true}
                    pageConfig={pageConfig}
                />
            );
        const addServiceInput = await waitFor(() =>
            getAllByTestId('input-node')
        );
        fireEvent.change(addServiceInput[0], {
            target: {
                value: 'test-name',
            },
        });
        fireEvent.change(addServiceInput[1], {
            target: {
                value: 'test-key',
            },
        });
        fireEvent.click(await waitFor(() => getByText('Submit')));
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error when after getService throws error(other)', async () => {
        const cancel = function () {};
        const domain = 'domain';
        const api = {
            addService: function (
                domainName,
                serviceName,
                description,
                endpoint,
                keyId,
                keyValue,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 1,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
            getServices: function (domainName, serviceName) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };
        MockApi.setMockApi(api);
        const { getByTestId, querySelector, getByText, getAllByTestId } =
            renderWithRedux(
                <AddService
                    onCancel={cancel}
                    domain={domain}
                    showAddService={true}
                    pageConfig={pageConfig}
                />
            );
        const addServiceInput = await waitFor(() =>
            getAllByTestId('input-node')
        );
        fireEvent.change(addServiceInput[0], {
            target: {
                value: 'test-name',
            },
        });
        fireEvent.change(addServiceInput[1], {
            target: {
                value: 'test-key',
            },
        });
        fireEvent.click(await waitFor(() => getByText('Submit')));
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });
});

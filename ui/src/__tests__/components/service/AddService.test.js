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
import AddService from '../../../components/service/AddService';
const pageConfig = {
    servicePageConfig: {
        keyCreationLink: {
            title: 'Key Creation',
            url:
                'https://test.com',
            target: '_blank',
        },
        keyCreationMessage:
            'Test Message',
    }
};
describe('AddService', () => {
    it('should render', () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {};
        const { getByTestId } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        const addService = getByTestId('add-service-form');
        expect(addService).toMatchSnapshot();
    });

    it('should render error after addService throws error(refresh)', async () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {
            addService: function(
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
            getService: function(
                domainName,
                serviceName
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 404,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
        };
        const {
            getByTestId,
            querySelector,
            getByText,
            getAllByTestId,
        } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = await waitForElement(() =>
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
        fireEvent.click(await waitForElement(() => getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error after addService throws error(other)', async () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {
            addService: function(
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
            getService: function(
                domainName,
                serviceName,
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 404,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
        };
        const {
            getByTestId,
            querySelector,
            getByText,
            getAllByTestId,
        } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = await waitForElement(() =>
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
        fireEvent.click(await waitForElement(() => getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should call onSubmit if add succeeds', async () => {
        const cancel = function() {};
        const domain = 'domain';
        let test = 0;
        const onSubmit = function(succedMessage) {
            test = test + 1;
        };
        const api = {
            addService: function(
                domainName,
                serviceName,
                description,
                endpoint,
                keyId,
                keyValue,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
            getService: function(
                domainName,
                serviceName,
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 404,
                        body: {
                            message: 'test-error',
                        },
                    });
                });
            },
        };
        const {
            getByTestId,
            querySelector,
            getByText,
            getAllByTestId,
        } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                onSubmit={onSubmit}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = await waitForElement(() =>
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
        fireEvent.click(await waitForElement(() => getByText('Submit')));
        expect(await waitForElement(() => test)).toEqual(1);
    });

    it('should render error if no key name specified', async () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {
            addService: function(
                domainName,
                serviceName,
                description,
                endpoint,
                keyId,
                keyValue,
                _csrf
            ) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
        };

        const {
            getByTestId,
            querySelector,
            getByText,
            getAllByTestId,
        } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        fireEvent.click(await waitForElement(() => getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error when service already exists', async () => {
        const cancel = function () {
        };
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
            getService: function (
                domainName,
                serviceName,
            ) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
        };
        const {
            getByTestId,
            querySelector,
            getByText,
            getAllByTestId,
        } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = await waitForElement(() =>
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
        fireEvent.click(await waitForElement(() => getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error when after getService throws error(other)', async () => {
        const cancel = function () {
        };
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
            getService: function (
                domainName,
                serviceName,
            ) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };
        const {
            getByTestId,
            querySelector,
            getByText,
            getAllByTestId,
        } = render(
            <AddService
                onCancel={cancel}
                domain={domain}
                api={api}
                showAddService={true}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = await waitForElement(() =>
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
        fireEvent.click(await waitForElement(() => getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });
});

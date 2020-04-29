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
import AddKey from '../../../components/service/AddKey';

describe('AddKey', () => {
    it('should render', () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {};
        const { getByTestId } = render(
            <AddKey cancel={cancel} domain={domain} api={api} />
        );
        const addKey = getByTestId('add-key');
        expect(addKey).toMatchSnapshot();
    });

    it('should render nothing after cancel', async () => {
        const api = {
            addKey: function(domainName, serviceName, keyId, keyValue, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        const cancel = function() {};
        const domain = 'domain';
        const { getByText, getByTestId, getByTitle } = render(
            <AddKey cancel={cancel} domain={domain} api={api} />
        );
        fireEvent.click(getByText('Cancel'));
        expect(
            await waitForElement(() => getByTestId('add-key'))
        ).toMatchSnapshot();
    });

    it('should render error after submit without keyID', async () => {
        const api = {
            addKey: function(domainName, serviceName, keyId, keyValue, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        const cancel = function() {};
        const domain = 'domain';
        const { getByText, getByTestId, getByTitle } = render(
            <AddKey cancel={cancel} domain={domain} api={api} />
        );
        fireEvent.click(getByText('Submit'));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error after submit without keyValue', async () => {
        const api = {
            addKey: function(domainName, serviceName, keyId, keyValue, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        const cancel = function() {};
        const domain = 'domain';
        const { getByText, getByTestId, getByTitle } = render(
            <AddKey cancel={cancel} domain={domain} api={api} />
        );
        fireEvent.change(getByTestId('input-node'), {
            target: {
                value: 'test-id',
            },
        });

        await waitForElement(() => fireEvent.click(getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error after submit throws error(refresh)', async () => {
        const api = {
            addKey: function(domainName, serviceName, keyId, keyValue, _csrf) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };
        const cancel = function() {};
        const domain = 'domain';
        const { getByText, getByTestId, getByTitle } = render(
            <AddKey cancel={cancel} domain={domain} api={api} />
        );
        fireEvent.change(getByTestId('input-node'), {
            target: {
                value: 'test-id',
            },
        });

        fireEvent.change(getByTestId('textarea'), {
            target: {
                value: 'test-value',
            },
        });

        await waitForElement(() => fireEvent.click(getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should render error after submit throws error(other)', async () => {
        const api = {
            addKey: function(domainName, serviceName, keyId, keyValue, _csrf) {
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
        const cancel = function() {};
        const domain = 'domain';
        const { getByText, getByTestId, getByTitle } = render(
            <AddKey cancel={cancel} domain={domain} api={api} />
        );
        fireEvent.change(getByTestId('input-node'), {
            target: {
                value: 'test-id',
            },
        });

        fireEvent.change(getByTestId('textarea'), {
            target: {
                value: 'test-value',
            },
        });

        await waitForElement(() => fireEvent.click(getByText('Submit')));
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
    });

    it('should trigger onSubmit after submit succeeds', async () => {
        const api = {
            addKey: function(domainName, serviceName, keyId, keyValue, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        let test = 1;
        const submit = function() {
            test = 2;
        };
        const cancel = function() {};
        const domain = 'domain';
        const { getByText, getByTestId, getByTitle } = render(
            <AddKey
                cancel={cancel}
                domain={domain}
                api={api}
                onSubmit={submit}
            />
        );
        fireEvent.change(getByTestId('input-node'), {
            target: {
                value: 'test-id',
            },
        });

        fireEvent.change(getByTestId('textarea'), {
            target: {
                value: 'test-value',
            },
        });

        await waitForElement(() => fireEvent.click(getByText('Submit')));
        expect(await waitForElement(() => test)).toEqual(2);
    });
});

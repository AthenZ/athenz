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
import ManageDomains from '../../../components/domain/ManageDomains';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('ManageDomains', () => {
    it('should render', () => {
        const domains = [
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    account: '111111',
                    ypmId: 0,
                    name: 'home.mujibur',
                    modified: '2018-01-31T19:43:14.476Z',
                    id: '77c25150-4f6a-11e6-a22d-0723ac92bd3d',
                },
            },
            {
                domain: {
                    description: 'test',
                    org: 'test',
                    enabled: true,
                    auditEnabled: false,
                    account: '14913436251',
                    ypmId: 0,
                    name: 'home.pgote',
                    modified: '2018-02-15T00:48:43.397Z',
                    id: '5fe71bb0-7642-11e7-8b74-f1fb574cabde',
                },
            },
        ];
        const api = {
            getMeta: function (params) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByTestId } = renderWithRedux(
            <ManageDomains domains={domains} api={api} />
        );
        const managedomains = getByTestId('manage-domains');

        expect(managedomains).toMatchSnapshot();
    });

    it('should render personal domain', () => {
        const domains = [
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    account: '111111',
                    ypmId: 0,
                    name: 'home.mujibur',
                    modified: '2018-01-31T19:43:14.476Z',
                    id: '77c25150-4f6a-11e6-a22d-0723ac92bd3d',
                },
            },
            {
                domain: {
                    description: 'test',
                    org: 'test',
                    enabled: true,
                    auditEnabled: false,
                    account: '14913436251',
                    ypmId: 0,
                    name: 'home.pgote',
                    modified: '2018-02-15T00:48:43.397Z',
                    id: '5fe71bb0-7642-11e7-8b74-f1fb574cabde',
                },
            },
        ];
        const api = {
            getMeta: function (params) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByTestId } = renderWithRedux(
            <ManageDomains domains={domains} api={api} />
        );
        const managedomains = getByTestId('manage-domains');

        expect(managedomains).toMatchSnapshot();
    });

    it('should render top level domain', () => {
        const domains = [
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    account: '111111',
                    ypmId: 0,
                    name: 'home.mujibur',
                    modified: '2018-01-31T19:43:14.476Z',
                    id: '77c25150-4f6a-11e6-a22d-0723ac92bd3d',
                },
            },
            {
                domain: {
                    description: 'test',
                    org: 'test',
                    enabled: true,
                    auditEnabled: false,
                    account: '14913436251',
                    ypmId: 0,
                    name: 'home',
                    modified: '2018-02-15T00:48:43.397Z',
                    id: '5fe71bb0-7642-11e7-8b74-f1fb574cabde',
                },
            },
        ];
        const api = {
            getMeta: function (params) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByTestId } = renderWithRedux(
            <ManageDomains domains={domains} api={api} />
        );
        const managedomains = getByTestId('manage-domains');

        expect(managedomains).toMatchSnapshot();
    });

    it('should render no domain', () => {
        const domains = [
            {
                domain: {
                    enabled: true,
                    auditEnabled: false,
                    account: '111111',
                    ypmId: 0,
                    name: 'home.mujibur',
                    modified: '2018-01-31T19:43:14.476Z',
                    id: '77c25150-4f6a-11e6-a22d-0723ac92bd3d',
                },
            },
            {
                domain: {
                    description: 'test',
                    org: 'test',
                    enabled: true,
                    auditEnabled: false,
                    account: '14913436251',
                    ypmId: 0,
                    name: 'home.mujibur.test',
                    modified: '2018-02-15T00:48:43.397Z',
                    id: '5fe71bb0-7642-11e7-8b74-f1fb574cabde',
                },
            },
        ];
        const api = {
            getMeta: function (params) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByTestId } = renderWithRedux(
            <ManageDomains domains={domains} api={api} />
        );
        const managedomains = getByTestId('manage-domains');

        expect(managedomains).toMatchSnapshot();
    });
});

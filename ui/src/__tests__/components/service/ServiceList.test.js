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
import ServiceList from '../../../components/service/ServiceList';
import {
    buildServicesForState,
    getStateWithServices,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
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
const domain = 'home.test';
const service = 'openhouse';
const fullServiceName = domain + '.' + service;
const servicesForState = buildServicesForState(
    {
        [fullServiceName]: {
            name: fullServiceName,
            modified: '2020-02-08T00:02:49.477Z',
        },
    },
    'home.test'
);

describe('ServiceList', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('should render without services', () => {
        const { getByTestId } = renderWithRedux(
            <ServiceList pageConfig={pageConfig} />
        );
        const servicelist = getByTestId('service-list');

        expect(servicelist).toMatchSnapshot();
    });

    it('should render with services', () => {
        const { getByTestId } = renderWithRedux(
            <ServiceList pageConfig={pageConfig} />,
            getStateWithServices(servicesForState)
        );
        const servicelist = getByTestId('service-list');

        expect(servicelist).toMatchSnapshot();
    });

    it('should render add service modal after click', async () => {
        const { getByText, getByTestId } = renderWithRedux(
            <ServiceList pageConfig={pageConfig} />,
            getStateWithServices(servicesForState)
        );
        fireEvent.click(getByText('Add Service'));
        expect(
            await waitFor(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render delete service modal error(refresh) after click', async () => {
        const api = {
            deleteService: function (domain, deleteServiceName, _csrf) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <ServiceList domain={domain} pageConfig={pageConfig} />,
            getStateWithServices(servicesForState)
        );
        fireEvent.click(getByTitle('trash'));

        await waitFor(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );
        expect(
            await waitFor(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render delete service modal error(other) after click', async () => {
        const api = {
            deleteService: function (domain, deleteServiceName, _csrf) {
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
            <ServiceList domain={domain} pageConfig={pageConfig} />,
            getStateWithServices(servicesForState)
        );
        fireEvent.click(getByTitle('trash'));

        await waitFor(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );
        expect(
            await waitFor(() => getByTestId('error-message'))
        ).toMatchSnapshot();
        expect(
            await waitFor(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render serviceList again after confirm delete', async () => {
        const api = {
            deleteService: function (domain, deleteServiceName, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <ServiceList domain={domain} pageConfig={pageConfig} />,
            getStateWithServices(servicesForState)
        );
        fireEvent.click(getByTitle('trash'));

        await waitFor(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );

        expect(
            await waitFor(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render serviceList again after cancel delete', async () => {
        const services = [
            {
                name: 'home.test1.openhouse',
                modified: '2020-02-08T00:02:49.477Z',
            },
        ];
        const api = {
            deleteService: function (domain, deleteServiceName, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
        };
        MockApi.setMockApi(api);

        const { getByText, getByTestId, getByTitle } = renderWithRedux(
            <ServiceList domain={domain} pageConfig={pageConfig} />,
            getStateWithServices(servicesForState)
        );
        fireEvent.click(getByTitle('trash'));

        await waitFor(() =>
            fireEvent.click(getByTestId('delete-modal-cancel'))
        );

        expect(
            await waitFor(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });
});

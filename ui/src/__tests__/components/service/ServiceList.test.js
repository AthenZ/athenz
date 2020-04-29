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
import ServiceList from '../../../components/service/ServiceList';
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
describe('ServiceList', () => {
    it('should render without services', () => {

        const { getByTestId } = render(<ServiceList pageConfig={pageConfig}/>);
        const servicelist = getByTestId('service-list');

        expect(servicelist).toMatchSnapshot();
    });

    it('should render with services', () => {
        const services = [
            {
                name: 'home.test.openhouse',
                modified: '2020-02-08T00:02:49.477Z',
            },
        ];
        const { getByTestId } = render(<ServiceList services={services} pageConfig={pageConfig}/>);
        const servicelist = getByTestId('service-list');

        expect(servicelist).toMatchSnapshot();
    });

    it('should render add service modal after click', async () => {
        const services = [
            {
                name: 'home.test.openhouse',
                modified: '2020-02-08T00:02:49.477Z',
            },
        ];
        const { getByText, getByTestId } = render(
            <ServiceList services={services} pageConfig={pageConfig}/>
        );
        fireEvent.click(getByText('Add Service'));
        expect(
            await waitForElement(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render delete service modal error(refresh) after click', async () => {
        const services = [
            {
                name: 'home.test1.openhouse',
                modified: '2020-02-08T00:02:49.477Z',
            },
        ];
        const api = {
            deleteService: function(domain, deleteServiceName, _csrf) {
                return new Promise((resolve, reject) => {
                    reject({
                        statusCode: 0,
                    });
                });
            },
        };
        const { getByText, getByTestId, getByTitle } = render(
            <ServiceList services={services} api={api} pageConfig={pageConfig}/>
        );
        fireEvent.click(getByTitle('trash'));

        await waitForElement(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );
        expect(
            await waitForElement(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render delete service modal error(other) after click', async () => {
        const services = [
            {
                name: 'home.test1.openhouse',
                modified: '2020-02-08T00:02:49.477Z',
            },
        ];
        const api = {
            deleteService: function(domain, deleteServiceName, _csrf) {
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
            <ServiceList services={services} api={api} pageConfig={pageConfig}/>
        );
        fireEvent.click(getByTitle('trash'));

        await waitForElement(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );
        expect(
            await waitForElement(() => getByTestId('error-message'))
        ).toMatchSnapshot();
        expect(
            await waitForElement(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });

    it('should render serviceList again after confirm delete', async () => {
        const services = [
            {
                name: 'home.test1.openhouse',
                modified: '2020-02-08T00:02:49.477Z',
            },
        ];
        const api = {
            deleteService: function(domain, deleteServiceName, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
            getServices: function(domain) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };

        const { getByText, getByTestId, getByTitle } = render(
            <ServiceList services={services} api={api} pageConfig={pageConfig} />
        );
        fireEvent.click(getByTitle('trash'));

        await waitForElement(() =>
            fireEvent.click(getByTestId('delete-modal-delete'))
        );

        expect(
            await waitForElement(() => getByTestId('service-list'))
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
            deleteService: function(domain, deleteServiceName, _csrf) {
                return new Promise((resolve, reject) => {
                    resolve();
                });
            },
            getServices: function(domain) {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };

        const { getByText, getByTestId, getByTitle } = render(
            <ServiceList services={services} api={api} pageConfig={pageConfig}/>
        );
        fireEvent.click(getByTitle('trash'));

        await waitForElement(() =>
            fireEvent.click(getByTestId('delete-modal-cancel'))
        );

        expect(
            await waitForElement(() => getByTestId('service-list'))
        ).toMatchSnapshot();
    });
});

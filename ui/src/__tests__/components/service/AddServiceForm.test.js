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
import AddServiceForm from '../../../components/service/AddServiceForm';
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
describe('AddServiceForm', () => {
    it('should render', () => {
        const cancel = function () {};
        const domain = 'domain';
        const { getByTestId } = render(
            <AddServiceForm
                cancel={cancel}
                domain={domain}
                pageConfig={pageConfig}
            />
        );
        const addServiceForm = getByTestId('add-service-form');
        expect(addServiceForm).toMatchSnapshot();
    });

    it('should render input for service name', async () => {
        const domain = 'domain';
        let test = 1;
        const onChange = function () {
            test = test + 1;
        };
        const { getByTestId, getAllByTestId } = render(
            <AddServiceForm
                domain={domain}
                onChange={onChange}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = getAllByTestId('input-node');
        fireEvent.change(addServiceInput[0], {
            target: {
                value: 'test-name',
            },
        });
        const addServiceInputAfterChange = await waitFor(() =>
            getAllByTestId('input-node')
        );
        expect(addServiceInputAfterChange[0].value).toEqual('test-name');
        expect(test).toEqual(2);
    });

    it('should render input for service description', async () => {
        const domain = 'domain';
        let test = 1;
        const onChange = function () {
            test = test + 1;
        };
        const { getByTestId, getAllByTestId } = render(
            <AddServiceForm
                domain={domain}
                onChange={onChange}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = getAllByTestId('input-node');
        fireEvent.change(addServiceInput[1], {
            target: {
                value: 'test-description',
            },
        });
        const addServiceInputAfterChange = await waitFor(() =>
            getAllByTestId('input-node')
        );
        expect(addServiceInputAfterChange[1].value).toEqual('test-description');
        expect(test).toEqual(2);
    });
    it('should render addKeyForm', async () => {
        const domain = 'domain';
        let test = 1;
        const onChange = function () {
            test = test + 1;
        };
        const { getByTestId, getAllByTestId } = render(
            <AddServiceForm
                domain={domain}
                onChange={onChange}
                pageConfig={pageConfig}
            />
        );
        const addServiceInput = getAllByTestId('input-node');
        fireEvent.change(addServiceInput[2], {
            target: {
                value: 'test-key',
            },
        });
        const addServiceInputAfterChange = await waitFor(() =>
            getAllByTestId('input-node')
        );
        expect(addServiceInputAfterChange[2].value).toEqual('test-key');
        expect(test).toEqual(2);
    });
});

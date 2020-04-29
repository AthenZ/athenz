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
import { fireEvent, render } from '@testing-library/react';
import AddAssertion from '../../../components/policy/AddAssertion';

describe('AddAssertion', () => {
    it('should render', () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {
            listRoles(domain) {
                return new Promise((resolve, reject) => {
                    resolve(['a, b']);
                });
            },
        };
        const { getByTestId } = render(
            <AddAssertion cancel={cancel} domain={domain} api={api} />
        );
        const addPolicy = getByTestId('add-assertion');
        expect(addPolicy).toMatchSnapshot();
    });

    it('should render failed to submit action is required', () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {
            listRoles(domain) {
                return new Promise((resolve, reject) => {
                    resolve(['a, b']);
                });
            },
        };
        const { getByTestId, getByText } = render(
            <AddAssertion cancel={cancel} domain={domain} api={api} />
        );
        const addPolicy = getByTestId('add-assertion');
        expect(addPolicy).toMatchSnapshot();

        fireEvent.click(getByText('Submit'));

        expect(getByText('Rule action is required.')).not.toBeNull();
    });

    it('should render failed to submit role name is required', () => {
        const cancel = function() {};
        const domain = 'domain';
        const api = {
            listRoles(domain) {
                return new Promise((resolve, reject) => {
                    resolve(['a, b']);
                });
            },
        };
        const { getByTestId, getByText, getByPlaceholderText } = render(
            <AddAssertion cancel={cancel} domain={domain} api={api} />
        );
        const addPolicy = getByTestId('add-assertion');
        expect(addPolicy).toMatchSnapshot();

        fireEvent.change(getByPlaceholderText('Rule Action'), {
            target: { value: 'ruleaction' },
        });
        fireEvent.click(getByText('Submit'));

        expect(getByText('Role name is required.')).not.toBeNull();
    });
});

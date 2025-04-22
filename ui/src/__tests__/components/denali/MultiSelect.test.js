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
import { fireEvent, render, waitFor } from '@testing-library/react';
import MultiSelect from '../../../components/denali/MultiSelect';

describe('MultiSelect', () => {
    const CLASSNAME_PREFIX = '.denali-multiselect';
    const AUTH_FILTER_ONSHORE = 'OnShore-US';
    const AUTH_FILTER_DATA_GOVERNANCE = 'DataGovernance';

    const onChange = jest.fn();

    afterEach(() => jest.clearAllMocks());

    const options = [
        { label: 'OnShore-US', value: 'OnShore-US'},
        { label: 'DataGovernance', value: 'DataGovernance'},
    ];

    it('renders initial (closed) state', () => {
        const { baseElement, getByTestId } = render(
            <MultiSelect options={options} onChange={onChange} selectedValues={''}/>
        );

        const multiselect = getByTestId('denali-multiselect');

        expect(
            baseElement.querySelector('.denali-multiselect__menu')
        ).toBeNull();

        expect(
            baseElement.querySelectorAll('.denali-multiselect__option')
        ).toHaveLength(0);

        expect(multiselect).toMatchSnapshot();
    });

    it('renders opened multiselect dropdown', async () => {
        const { baseElement, getByTestId } = render(
            <MultiSelect
                options={options}
                onChange={onChange}
                selectedValues={''}
            />
        );

        const multiselect = baseElement.querySelector(`${CLASSNAME_PREFIX}__control`);
        fireEvent.mouseDown(multiselect);

        await waitFor(() =>
            baseElement.querySelector(`${CLASSNAME_PREFIX}__menu`)
        );

        const dropdownItems = baseElement.querySelectorAll(`${CLASSNAME_PREFIX}__option`);

        expect(dropdownItems).toHaveLength(options.length);
    });

    it('renders with default selected item', () => {
        const { baseElement, getByTestId } = render(
            <MultiSelect
                options={options}
                onChange={onChange}
                selectedValues={AUTH_FILTER_ONSHORE}
            />
        );

        const selectedOptions = baseElement.querySelectorAll(`${CLASSNAME_PREFIX}__multi-value__label`);

        expect(selectedOptions.length).toBe(1);
        expect(selectedOptions[0].textContent).toEqual(AUTH_FILTER_ONSHORE);
    });

    it('can remove a selected item', async () => {
        const { baseElement } = render(
            <MultiSelect
                options={options}
                onChange={onChange}
                selectedValues={`${AUTH_FILTER_ONSHORE},${AUTH_FILTER_DATA_GOVERNANCE}`}
            />
        );

        let selectedOptions = baseElement.querySelectorAll(`${CLASSNAME_PREFIX}__multi-value__label`);
        const removeButtons = baseElement.querySelectorAll(`${CLASSNAME_PREFIX}__multi-value__remove`);

        expect(selectedOptions).toHaveLength(options.length);
        expect(removeButtons).toHaveLength(options.length);
        expect(selectedOptions[0].textContent).toEqual(AUTH_FILTER_ONSHORE);
        expect(selectedOptions[1].textContent).toEqual(AUTH_FILTER_DATA_GOVERNANCE);

        fireEvent.click(removeButtons[1]);

        await waitFor(() => {
            expect(selectedOptions[1]).not.toBeInTheDocument();
        })

        selectedOptions = baseElement.querySelectorAll(`${CLASSNAME_PREFIX}__multi-value__label`);

        expect(selectedOptions).toHaveLength(1);
        expect(selectedOptions[0].textContent).toEqual(AUTH_FILTER_ONSHORE);
    });

    it('can open the multiselect menu and select an item', async () => {
        const { baseElement, getByTestId } = render(
            <MultiSelect
                options={options}
                onChange={onChange}
                selectedValues={''}
            />
        );

        const multiselect = baseElement.querySelector(`${CLASSNAME_PREFIX}__control`);
        fireEvent.mouseDown(multiselect);

        await waitFor(() =>
            baseElement.querySelector(`${CLASSNAME_PREFIX}__menu`)
        );

        const dropdownItem = baseElement.querySelector(`${CLASSNAME_PREFIX}__option`);
        fireEvent.click(dropdownItem);

        const selectedOptions = baseElement.querySelectorAll(`${CLASSNAME_PREFIX}__multi-value__label`);

        expect(selectedOptions).toHaveLength(1);
    });
});
